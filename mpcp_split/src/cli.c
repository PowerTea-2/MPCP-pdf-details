/* AethroSync — src/cli.c — main_test, contacts, fw, bench, selftest, listen, transfer */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <termios.h>
#include <stdatomic.h>
#include <sodium.h>
#include <zstd.h>
#include "../include/mpcp.h"

#include "../include/ui.h"

int main_test(void)
{
  int rc1 = mpcp_test_core_main();
  printf("\n");
  int rc2 = mpcp_test_phase3_main();
  return (rc1 == 0 && rc2 == 0) ? 0 : 1;
}



/* Forward declarations for CLI helpers used by firewall code */
bool ask_yn(const char *question, bool default_yes);
int  read_line(const char *prompt, char *buf, size_t size);

/* =========================================================
 * Firewall helper
 *
 * Detects firewalld / ufw / iptables and temporarily opens
 * the ports needed for a transfer session.
 * Requests sudo if not already root.
 * ========================================================= */

typedef enum {
    FW_NONE,
    FW_FIREWALLD,
    FW_UFW,
    FW_IPTABLES,
} fw_type_t;

static fw_type_t fw_detect(void)
{
    if (system("command -v firewall-cmd >/dev/null 2>&1") == 0 &&
        system("systemctl is-active --quiet firewalld 2>/dev/null") == 0)
        return FW_FIREWALLD;
    if (system("command -v ufw >/dev/null 2>&1") == 0 &&
        system("ufw status 2>/dev/null | grep -q 'Status: active'") == 0)
        return FW_UFW;
    if (system("command -v iptables >/dev/null 2>&1") == 0)
        return FW_IPTABLES;
    return FW_NONE;
}

static const char *fw_name(fw_type_t fw)
{
    switch (fw) {
        case FW_FIREWALLD: return "firewalld";
        case FW_UFW:       return "ufw";
        case FW_IPTABLES:  return "iptables";
        default:           return "none";
    }
}

/* Run a command with sudo if not root. Returns exit code. */
static int sudo_run(const char *cmd)
{
    char buf[512];
    if (geteuid() == 0)
        snprintf(buf, sizeof(buf), "%s", cmd);
    else
        snprintf(buf, sizeof(buf), "sudo %s", cmd);
    return system(buf);
}

static void fw_open_ports(fw_type_t fw, uint16_t base, uint32_t range)
{
    char cmd[256];
    uint32_t top = (uint32_t)base + range - 1u;
    if (top > 65535u) top = 65535u;

    switch (fw) {
        case FW_FIREWALLD:
            snprintf(cmd, sizeof(cmd),
                "firewall-cmd --add-port=%u-%u/udp 2>/dev/null", base, (uint16_t)top);
            sudo_run(cmd);
            break;
        case FW_UFW:
            snprintf(cmd, sizeof(cmd),
                "ufw allow %u:%u/udp 2>/dev/null", base, (uint16_t)top);
            sudo_run(cmd);
            break;
        case FW_IPTABLES:
            /* -I INPUT 1 inserts at the TOP of the chain.
             * -A appends to the END — any DROP/REJECT rule above it
             * would match first and silently block all kex packets. */
            snprintf(cmd, sizeof(cmd),
                "iptables -I INPUT 1 -p udp --dport %u:%u -j ACCEPT 2>/dev/null",
                base, (uint16_t)top);
            sudo_run(cmd);
            break;
        default:
            break;
    }
}

static void fw_close_ports(fw_type_t fw, uint16_t base, uint32_t range)
{
    char cmd[256];
    uint32_t top = (uint32_t)base + range - 1u;
    if (top > 65535u) top = 65535u;

    switch (fw) {
        case FW_FIREWALLD:
            snprintf(cmd, sizeof(cmd),
                "firewall-cmd --remove-port=%u-%u/udp 2>/dev/null", base, (uint16_t)top);
            sudo_run(cmd);
            break;
        case FW_UFW:
            snprintf(cmd, sizeof(cmd),
                "ufw delete allow %u:%u/udp 2>/dev/null", base, (uint16_t)top);
            sudo_run(cmd);
            break;
        case FW_IPTABLES:
            /* Delete by full rule specification to match exactly what we inserted */
            snprintf(cmd, sizeof(cmd),
                "iptables -D INPUT -p udp --dport %u:%u -j ACCEPT 2>/dev/null",
                base, (uint16_t)top);
            sudo_run(cmd);
            break;
        default:
            break;
    }
}

static fw_type_t g_fw_active = FW_NONE;
static uint16_t  g_fw_base   = 0;
static uint32_t  g_fw_range  = 0;

/* Call once before transfer; call fw_cleanup() after. */
void fw_maybe_open(uint16_t base, uint32_t range)
{
    fw_type_t fw = fw_detect();
    if (fw == FW_NONE) return;

    printf("\n  Detected firewall: %s\n", fw_name(fw));
    printf("  MPCP needs UDP ports %u-%u open to receive.\n",
           base, (uint16_t)((uint32_t)base + range - 1u));
    if (!ask_yn("  Temporarily open these ports? (requires sudo)", true))
        return;

    fw_open_ports(fw, base, range);
    g_fw_active = fw;
    g_fw_base   = base;
    g_fw_range  = range;
    printf("  -> ports opened (will be closed after transfer)\n");
}

void fw_cleanup(void)
{
    if (g_fw_active == FW_NONE) return;
    printf("  Closing firewall ports...\n");
    fw_close_ports(g_fw_active, g_fw_base, g_fw_range);
    g_fw_active = FW_NONE;
}


/* =========================================================
 * Progress bar
 *
 * Brutalist ASCII block style.  Only draws on a real TTY;
 * falls back to periodic line updates in pipes / logs.
 *
 * Usage:
 *   progress_t p;
 *   progress_init(&p, "Sending", total_chunks);
 *   progress_update(&p, done_chunks);   // call repeatedly
 *   progress_done(&p, ok);
 * ========================================================= */

typedef struct {
    const char *label;
    uint32_t    total;
    uint32_t    last_drawn;
    bool        is_tty;
    uint64_t    start_ns;
} progress_t;

#define PBAR_WIDTH 40

static void __attribute__((unused)) progress_init(progress_t *p, const char *label, uint32_t total)
{
    p->label      = label;
    p->total      = total > 0 ? total : 1;
    p->last_drawn = UINT32_MAX;
    p->is_tty     = isatty(STDERR_FILENO);
    p->start_ns   = mpcp_now_ns();
}

static void __attribute__((unused)) progress_draw(progress_t *p, uint32_t done)
{
    if (done == p->last_drawn) return;
    p->last_drawn = done;

    uint32_t pct   = (uint32_t)(((uint64_t)done * 100u) / p->total);
    uint32_t fill  = (uint32_t)(((uint64_t)done * PBAR_WIDTH) / p->total);
    uint64_t elapsed_ms = (mpcp_now_ns() - p->start_ns) / 1000000u;
    double   speed = (elapsed_ms > 0)
                     ? (double)done / ((double)elapsed_ms / 1000.0)
                     : 0.0;

    if (p->is_tty) {
        if (g_ui_colour) {
            /* Purple gradient bar with glowing head */
            fprintf(stderr, "\r  %s%s%s [", C_GREY, p->label, C_RESET);
            for (uint32_t i = 0; i < PBAR_WIDTH; i++) {
                if (i < fill) {
                    /* Head cell: bright plum; tail: medium violet */
                    if (i == fill - 1)
                        fprintf(stderr, "%s\xe2\x96\x88%s", C_PLUM, C_RESET);
                    else
                        fprintf(stderr, "%s\xe2\x96\x88%s", C_VIOLET, C_RESET);
                } else if (i == fill) {
                    /* Glow bleed: half-block right after head */
                    fprintf(stderr, "%s\xe2\x96\x8c%s", C_GRAPE, C_RESET);
                } else {
                    fprintf(stderr, "%s\xe2\x96\x91%s", C_GRAPE, C_RESET);
                }
            }
            fprintf(stderr, "] %s%3u%%%s  %u/%u  %s%.1f c/s%s   ",
                    C_PLUM, pct, C_RESET,
                    done, p->total,
                    C_GREY, speed, C_RESET);
        } else {
            fprintf(stderr, "\r  %s [", p->label);
            for (uint32_t i = 0; i < PBAR_WIDTH; i++) {
                if (i < fill) { fputc(0xE2,stderr);fputc(0x96,stderr);fputc(0x88,stderr); }
                else          { fputc(0xE2,stderr);fputc(0x96,stderr);fputc(0x91,stderr); }
            }
            fprintf(stderr, "] %3u%%  %u/%u  %.1f c/s   ",
                    pct, done, p->total, speed);
        }
        fflush(stderr);
    } else {
        if (pct % 25 == 0 && pct != 100)
            fprintf(stderr, "  %s: %u%%  (%u/%u chunks)\n",
                    p->label, pct, done, p->total);
    }
}

static void __attribute__((unused)) progress_update(progress_t *p, uint32_t done)
{
    progress_draw(p, done);
}

static void __attribute__((unused)) progress_done(progress_t *p, bool ok)
{
    uint64_t elapsed_ms = (mpcp_now_ns() - p->start_ns) / 1000000u;
    if (p->is_tty) {
        if (ok) {
            if (g_ui_colour) {
                fprintf(stderr, "\r  %s%s%s [", C_GREY, p->label, C_RESET);
                for (uint32_t i = 0; i < PBAR_WIDTH; i++)
                    fprintf(stderr, "%s\xe2\x96\x88%s", C_LIME, C_RESET);
                fprintf(stderr, "] %s100%%%s  %u/%u  %s%.2fs%s   \n",
                        C_LIME, C_RESET, p->total, p->total,
                        C_GREY, (double)elapsed_ms/1000.0, C_RESET);
            } else {
                fprintf(stderr, "\r  %s [", p->label);
                for (uint32_t i = 0; i < PBAR_WIDTH; i++)
                { fputc(0xE2,stderr);fputc(0x96,stderr);fputc(0x88,stderr); }
                fprintf(stderr, "] 100%%  %u/%u  %.2fs   \n",
                        p->total, p->total, (double)elapsed_ms / 1000.0);
            }
        } else {
            if (g_ui_colour)
                fprintf(stderr, "\r  %s%s%s %s[FAILED]%s  after %.2fs\n",
                        C_GREY, p->label, C_RESET,
                        C_ROSE, C_RESET, (double)elapsed_ms/1000.0);
            else
                fprintf(stderr, "\r  %s [FAILED]  after %.2fs\n",
                        p->label, (double)elapsed_ms / 1000.0);
        }
    } else {
        fprintf(stderr, "  %s: %s  (%.2fs)\n",
                p->label, ok ? "done" : "FAILED", (double)elapsed_ms / 1000.0);
    }
    fflush(stderr);
}

/* Progress polling thread - polls atomic counter and redraws bar */
typedef struct {
    progress_t       *bar;
    _Atomic(uint32_t) *counter;
    volatile int       done;
} progress_poll_t;

static __attribute__((used)) void *progress_poll_thread(void *arg)
{
    progress_poll_t *pp = (progress_poll_t *)arg;
    while (!pp->done) {
        uint32_t v = atomic_load_explicit(pp->counter, memory_order_relaxed);
        progress_update(pp->bar, v);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 150000000L }; /* 150ms */
        nanosleep(&ts, NULL);
    }
    return NULL;
}


/* =========================================================
 * Contacts
 *
 * Stored in ~/.config/mpcp/contacts -- one entry per line:
 *   alias  IP  port
 * e.g.
 *   alice  192.168.1.50  10000
 *   bob    10.0.0.7      10000
 * ========================================================= */

#define MAX_CONTACTS  64
#define ALIAS_LEN     64

typedef struct {
    char     alias[ALIAS_LEN];
    char     ip[128];
    uint16_t port;
} mpcp_contact_t;

static mpcp_contact_t contacts[MAX_CONTACTS];
static int            contact_count = 0;

static void contacts_path(char *out, size_t size)
{
    const char *home = getenv("HOME");
    if (!home) home = "~";
    snprintf(out, size, "%s/.config/mpcp/contacts", home);
}

void contacts_load(void)
{
    char path[512];
    contacts_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f) && contact_count < MAX_CONTACTS) {
        if (line[0] == '#' || line[0] == '\n') continue;
        mpcp_contact_t *c = &contacts[contact_count];
        unsigned port = 10000;
        if (sscanf(line, "%63s %15s %u", c->alias, c->ip, &port) >= 2) {
            c->port = (uint16_t)port;
            contact_count++;
        }
    }
    fclose(f);
}

static void contacts_save(void)
{
    /* Ensure directory exists */
    char dir[512];
    const char *home = getenv("HOME");
    if (!home) home = "~";
    snprintf(dir, sizeof(dir), "%s/.config/mpcp", home);
    mkdir(dir, 0700);

    char path[512];
    contacts_path(path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "  warning: could not save contacts to %s\n", path); return; }
    fprintf(f, "# MPCP contacts: alias  IP  port\n");
    for (int i = 0; i < contact_count; i++)
        fprintf(f, "%s  %s  %u\n",
                contacts[i].alias, contacts[i].ip, contacts[i].port);
    fclose(f);
}

/* Find contact by alias. Returns pointer or NULL. */
static mpcp_contact_t *contact_find(const char *alias)
{
    for (int i = 0; i < contact_count; i++)
        if (strcmp(contacts[i].alias, alias) == 0)
            return &contacts[i];
    return NULL;
}

/* =========================================================
 * Terminal helpers
 * ========================================================= */

int read_line(const char *prompt, char *buf, size_t size)
{
    if (g_ui_colour)
        printf("  %s" GLYPH_ARR " %s%s%s ", C_GRAPE, C_VIOLET, prompt, C_RESET);
    else
        printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)size, stdin)) return -1;
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

static __attribute__((unused)) int read_line_noecho(const char *prompt, char *buf, size_t size)
{
    if (g_ui_colour)
        printf("  %s" GLYPH_LOCK " %s%s%s ", C_GRAPE, C_VIOLET, prompt, C_RESET);
    else
        printf("%s", prompt);
    fflush(stdout);
    struct termios old, noecho;
    tcgetattr(STDIN_FILENO, &old);
    noecho = old;
    noecho.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    int rc = read_line("", buf, size);
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
    return rc;
}

bool ask_yn(const char *question, bool default_yes)
{
    char buf[8];
    if (g_ui_colour)
        printf("  %s%s%s [%s%s%s] ",
               C_WHITE, question, C_RESET,
               C_PLUM, default_yes ? "Y/n" : "y/N", C_RESET);
    else
        printf("%s [%s] ", question, default_yes ? "Y/n" : "y/N");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return default_yes;
    buf[strcspn(buf, "\n")] = '\0';
    if (buf[0] == '\0') return default_yes;
    return (buf[0] == 'y' || buf[0] == 'Y');
}

void banner(const char *title)
{
    if (g_ui_colour) {
        /* Animated: draw left corner, title, then rule character by character */
        printf("\n  %s\xe2\x94\x8c\xe2\x94\x80\xe2\x94\x80%s %s" GLYPH_GEM " %s%s%s%s ",
               C_GRAPE, C_RESET, C_PLUM, C_BOLD, title, C_RESET, C_RESET);
        int used = 9 + (int)strlen(title);
        printf("%s", C_GRAPE);
        for (int i = used; i < 60; i++) {
            printf("\xe2\x94\x80");
            fflush(stdout);
        }
        printf("\xe2\x94\x90%s\n", C_RESET);
    } else {
        printf("\n-- %s ", title);
        int len = 4 + (int)strlen(title);
        for (int i = len; i < 60; i++) putchar('-');
        printf("\n");
    }
}


/* =========================================================
 * Spinner
 *
 * Runs a portage-style \ | / - spinner in a background thread
 * while a blocking operation executes.
 *
 * Usage:
 *   spinner_t sp;
 *   spinner_start(&sp, "  Measuring RTT");
 *   rc = mpcp_calibrate(...);
 *   spinner_stop(&sp, rc == MPCP_OK);
 * ========================================================= */

typedef struct {
    pthread_t       thread;
    volatile int    done;     /* set to 1 to stop, 2 to stop+ok, 3 to stop+fail */
} spinner_t;

static void *spinner_thread(void *arg)
{
    spinner_t *sp = (spinner_t *)arg;
    /* Braille 10-frame dot spinner */
    static const char *bf[] = {
        "\xe2\xa0\x8b","\xe2\xa0\x99","\xe2\xa0\xb9","\xe2\xa0\xb8",
        "\xe2\xa0\xbc","\xe2\xa0\xb4","\xe2\xa0\xa6","\xe2\xa0\xa7",
        "\xe2\xa0\x87","\xe2\xa0\x8f",
    };
    /* Colour cycles through purple shades to create glow effect */
    static const char *gcols[] = {
        "\033[38;2;160;80;220m",
        "\033[38;2;180;100;240m",
        "\033[38;2;200;130;255m",
        "\033[38;2;220;160;255m",
        "\033[38;2;200;130;255m",
        "\033[38;2;180;100;240m",
    };
    static const char pf[] = { '|', '/', '-', '\\' };
    int idx = 0;
    while (!sp->done) {
        if (g_ui_colour)
            printf("\r  %s%s%s ", gcols[idx % 6], bf[idx % 10], C_RESET);
        else
            printf("\r  %c ", pf[idx & 3]);
        fflush(stdout);
        idx++;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 70000000L };
        nanosleep(&ts, NULL);
    }
    if (sp->done == 2) {
        if (g_ui_colour)
            printf("\r  %s" GLYPH_OK "%s  done          \n", C_LIME, C_RESET);
        else
            printf("\r  done          \n");
    } else if (sp->done == 3) {
        if (g_ui_colour)
            printf("\r  %s" GLYPH_FAIL "%s  failed        \n", C_ROSE, C_RESET);
        else
            printf("\r  failed        \n");
    } else {
        printf("\r                  \n");
    }
    fflush(stdout);
    return NULL;
}

void spinner_start(spinner_t *sp, const char *label)
{
    sp->done = 0;
    if (g_ui_colour)
        printf("  %s%s%s\n", C_GREY, label, C_RESET);
    else
        printf("%s...\n", label);
    fflush(stdout);
    pthread_create(&sp->thread, NULL, spinner_thread, sp);
}

void spinner_stop(spinner_t *sp, bool ok)
{
    sp->done = ok ? 2 : 3;
    pthread_join(sp->thread, NULL);
}


/* =========================================================
 * Contact management prompts
 * ========================================================= */

void cmd_contacts(void)
{
    banner("Contacts");
    if (contact_count == 0) {
        printf("  (no contacts saved yet)\n");
    } else {
        printf("  %-20s  %-16s  %s\n", "Alias", "IP", "Port");
        printf("  %-20s  %-16s  %s\n", "-----", "--", "----");
        for (int i = 0; i < contact_count; i++)
            printf("  %-20s  %-16s  %u\n",
                   contacts[i].alias, contacts[i].ip, contacts[i].port);
    }
    printf("\n  a) Add contact\n");
    printf("  d) Delete contact\n");
    printf("  q) Back\n");
    char buf[8];
    read_line("\nChoice: ", buf, sizeof(buf));

    if (buf[0] == 'a' || buf[0] == 'A') {
        if (contact_count >= MAX_CONTACTS) {
            printf("  Contact list full.\n"); return;
        }
        mpcp_contact_t *c = &contacts[contact_count];
        read_line("  Alias (e.g. alice): ", c->alias, ALIAS_LEN);
        if (c->alias[0] == '\0') { printf("  Cancelled.\n"); return; }
        if (contact_find(c->alias)) {
            printf("  Alias '%s' already exists.\n", c->alias); return;
        }
        read_line("  IP address: ", c->ip, sizeof(c->ip));
        char port_buf[16];
        read_line("  Port [default 10000]: ", port_buf, sizeof(port_buf));
        c->port = (port_buf[0] != '\0') ? (uint16_t)atoi(port_buf) : 10000;
        contact_count++;
        contacts_save();
        printf("  -> saved %s (%s:%u)\n", c->alias, c->ip, c->port);

    } else if (buf[0] == 'd' || buf[0] == 'D') {
        char alias[ALIAS_LEN];
        read_line("  Alias to delete: ", alias, sizeof(alias));
        for (int i = 0; i < contact_count; i++) {
            if (strcmp(contacts[i].alias, alias) == 0) {
                contacts[i] = contacts[--contact_count];
                contacts_save();
                printf("  -> deleted '%s'\n", alias);
                return;
            }
        }
        printf("  Not found.\n");
    }
}

/* =========================================================
 * Resolve peer: alias or raw IP:port
 * ========================================================= */

static int resolve_peer(struct sockaddr_in *out)
{
    char buf[128];
    if (contact_count > 0) {
        printf("  Contacts: ");
        for (int i = 0; i < contact_count; i++)
            printf("%s%s", contacts[i].alias, i < contact_count-1 ? ", " : "");
        printf("\n");
        read_line("  Alias or IP: ", buf, sizeof(buf));
    } else {
        read_line("  Receiver IP: ", buf, sizeof(buf));
    }

    if (buf[0] == '\0') return -1;

    mpcp_contact_t *c = contact_find(buf);
    if (c) {
        printf("  -> %s (%s:%u)\n", c->alias, c->ip, c->port);
        out->sin_family = AF_INET;
        out->sin_port   = htons(c->port);
        return (inet_pton(AF_INET, c->ip, &out->sin_addr) == 1) ? 0 : -1;
    }

    /* Raw IP -- ask for port separately */
    char port_buf[16];
    read_line("  Port [default 10000]: ", port_buf, sizeof(port_buf));
    uint16_t port = (port_buf[0] != '\0') ? (uint16_t)atoi(port_buf) : 10000;
    out->sin_family = AF_INET;
    out->sin_port   = htons(port);
    if (inet_pton(AF_INET, buf, &out->sin_addr) != 1) {
        fprintf(stderr, "  error [peer address]: not a valid IPv4 address\n");
        return -1;
    }

    /* Reject broadcast and multicast - common mistakes */
    uint32_t ip_h = ntohl(out->sin_addr.s_addr);
    if ((ip_h & 0xFF) == 0xFF) {
        fprintf(stderr, "  error [peer address]: %s looks like a broadcast address\n", buf);
        fprintf(stderr, "  hint:  use the receiver\'s actual IP (run \'ip addr\' or \'ifconfig\' on their machine)\n");
        return -1;
    }
    if ((ip_h >> 28) == 0xE) {
        fprintf(stderr, "  error [peer address]: %s is a multicast address\n", buf);
        return -1;
    }
    if (ip_h == 0x7F000001u) {
        /* 127.0.0.1 is fine for local testing - allow it but warn */
        printf("  (loopback - for local testing only)\n");
    }

    /* Offer to save as a contact */
    if (ask_yn("  Save this peer as a contact?", false)) {
        if (contact_count < MAX_CONTACTS) {
            mpcp_contact_t *nc = &contacts[contact_count];
            read_line("  Alias: ", nc->alias, ALIAS_LEN);
            if (nc->alias[0] != '\0') {
                snprintf(nc->ip, sizeof(nc->ip), "%s", buf);
                nc->port = port;
                contact_count++;
                contacts_save();
                printf("  -> saved as '%s'\n", nc->alias);
            }
        }
    }

    printf("  -> connecting to %s:%u\n", buf, port);
    return 0;
}

/* =========================================================
 * Transfer session
 * ========================================================= */

/* =========================================================
 * Transfer info exchange
 *
 * After key exchange the sender tells the receiver exactly how
 * many chunks to expect. Without this the receiver can't open
 * the right number of catch ports.
 *
 * Protocol:
 *   - Port derived from session_key + "xfer-info" tag (unique per session)
 *   - Payload: n_chunks(4 BE) + flags(1) = 5 bytes plaintext
 *   - Encrypted with XChaCha20-Poly1305 keyed on session_key
 *   - Receiver opens the port first, sender sends to it
 *   - 10s timeout on receiver side
 * ========================================================= */

/* Derive the transfer-info port from session_key */
static uint16_t xfer_info_port(const mpcp_session_t *sess,
                                const mpcp_config_t  *cfg)
{
    uint8_t out[4];
    const uint8_t *ikm = (const uint8_t *)"xfer-info";
    if (mpcp_hkdf(sess->session_key, MPCP_SESSION_KEY_LEN,
                  ikm, 9,
                  "mpcp-v0.5-xfer-info", out, 4) != MPCP_OK) {
        /* Deterministic fallback */
        return (uint16_t)((cfg->port_base + 1u) % 65535u);
    }
    uint32_t seed = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
                    ((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
    return (uint16_t)(seed % cfg->port_range + cfg->port_base);
}

/* Sender: encrypt and send n_chunks + flags to receiver */
static int transfer_info_send(const mpcp_session_t *sess,
                               const mpcp_config_t  *cfg,
                               const struct sockaddr_in *peer_addr,
                               uint32_t n_chunks,
                               uint8_t  flags)
{
    /* Plaintext: n_chunks(4 BE) | flags(1) */
    uint8_t plain[5];
    plain[0] = (uint8_t)((n_chunks >> 24) & 0xFF);
    plain[1] = (uint8_t)((n_chunks >> 16) & 0xFF);
    plain[2] = (uint8_t)((n_chunks >>  8) & 0xFF);
    plain[3] = (uint8_t)( n_chunks        & 0xFF);
    plain[4] = flags;

    /* Nonce: first 24 bytes of session_key (safe - key is 32B) */
    uint8_t nonce[24];
    memcpy(nonce, sess->session_key, 24);

    /* Ciphertext: 5 + 16 (poly tag) = 21 bytes */
    uint8_t ct[21];
    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len,
            plain, sizeof(plain),
            NULL, 0,
            NULL, nonce, sess->session_key) != 0)
        return MPCP_ERR_CRYPTO;

    uint16_t port = xfer_info_port(sess, cfg);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return MPCP_ERR_IO;

    struct sockaddr_in dst = *peer_addr;
    dst.sin_port = htons(port);

    /* Retry a few times in case receiver isn't ready yet */
    for (int i = 0; i < 5; i++) {
        sendto(sock, ct, (size_t)ct_len, 0,
               (struct sockaddr *)&dst, sizeof(dst));
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000000L }; /* 200ms */
        nanosleep(&ts, NULL);
    }
    close(sock);
    return MPCP_OK;
}

/* Receiver: wait for and decrypt transfer info from sender */
int transfer_info_recv(const mpcp_session_t *sess,
                               const mpcp_config_t  *cfg,
                               uint32_t *n_chunks_out,
                               uint8_t  *flags_out)
{
    uint16_t port = xfer_info_port(sess, cfg);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return MPCP_ERR_IO;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return MPCP_ERR_IO;
    }

    /* 10 second wait for sender */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t ct[32]; /* 21 bytes expected + slack */
    ssize_t n = recv(fd, ct, sizeof(ct), 0);
    close(fd);

    if (n != 21) return MPCP_ERR_TIMEOUT;

    uint8_t nonce[24];
    memcpy(nonce, sess->session_key, 24);

    uint8_t plain[5];
    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain, &pt_len,
            NULL,
            ct, (unsigned long long)n,
            NULL, 0,
            nonce, sess->session_key) != 0)
        return MPCP_ERR_CRYPTO;

    if (pt_len != 5) return MPCP_ERR_PROTO;

    *n_chunks_out = ((uint32_t)plain[0] << 24) |
                    ((uint32_t)plain[1] << 16) |
                    ((uint32_t)plain[2] <<  8) |
                     (uint32_t)plain[3];
    *flags_out    = plain[4];

    return MPCP_OK;
}

/* =========================================================
 * Pong reflection server (PC1 / receiver side of calibration)
 *
 * Spec S7: PC2 sends pings, PC1 reflects them as pongs.
 * PC1 has no RTT samples of its own - it just echoes back.
 * Runs until the sender stops sending (2s idle timeout) or
 * we have reflected enough pings.
 * ========================================================= */
/* pong_server - reflect calibration pings back to sender.
 * Outputs:
 *   sender_addr_out : filled with the sender's IP:port on return
 *   nonce_hint_out  : first 16 bytes of sender's session nonce
 * Returns 0 on success, -1 on bind failure. */
int pong_server(const mpcp_config_t *cfg,
                        struct sockaddr_in  *sender_addr_out,
                        uint8_t             *nonce_hint_out,
                        bool                 prompt_accept)
{
    /* Bind on port_base so PC2 knows where to aim pings */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("pong_server: socket"); return -1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)cfg->port_base);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("pong_server: bind");
        close(fd);
        return -1;
    }

    uint8_t buf[512];
    struct sockaddr_in sender;
    socklen_t slen = sizeof(sender);

    /* Phase 1: wait indefinitely for the FIRST valid ping.
     * No timeout here - we block until the sender actually shows up. */
    {
        struct timeval tv_inf = { .tv_sec = 0, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_inf, sizeof(tv_inf));
    }

    bool got_first = false;
    while (!got_first) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&sender, &slen);
        if (n <= 0) continue;

        uint8_t pkt_buf[sizeof(mpcp_cal_pkt_t) + 64];
        size_t  pkt_len = (size_t)n;
        if (cfg->disguise_calibration) {
            pkt_len = mpcp_disguise_unwrap(buf, (size_t)n,
                                           pkt_buf, sizeof(pkt_buf),
                                           cfg->disguise_protocol);
            if (pkt_len == 0) continue;
        } else {
            if ((size_t)n > sizeof(pkt_buf)) continue;
            memcpy(pkt_buf, buf, (size_t)n);
        }
        if (pkt_len < sizeof(mpcp_cal_pkt_t)) continue;
        mpcp_cal_pkt_t *ping = (mpcp_cal_pkt_t *)pkt_buf;
        uint32_t magic;
        memcpy(&magic, &ping->hdr.magic, 4);
        if (ntohl(magic) != MPCP_MAGIC) continue;
        if (ping->hdr.version != MPCP_VERSION) continue;
        if (ping->hdr.type != MPCP_TYPE_PING) continue;
        /* Capture sender address and nonce_hint for caller.
         * The receiver uses the sender's nonce to derive the same master secret. */
        if (sender_addr_out)
            memcpy(sender_addr_out, &sender, sizeof(sender));
        if (nonce_hint_out)
            memcpy(nonce_hint_out, ping->nonce_hint, MPCP_NONCE_HINT_LEN);
        got_first = true;
        fprintf(stderr, "\r  [ping 1] received from %s              \n",
                inet_ntoa(sender.sin_addr));

        /* Server listen mode: ask operator before accepting */
        if (prompt_accept) {
            char ans[8];
            fprintf(stderr, "  Accept connection from %s? [Y/n] ",
                    inet_ntoa(sender.sin_addr));
            fflush(stderr);
            if (fgets(ans, sizeof(ans), stdin) == NULL || (ans[0] == 'n' || ans[0] == 'N')) {
                fprintf(stderr, "  Connection rejected.\n");
                close(fd);
                return -2;  /* -2 = rejected, caller loops back */
            }
        } else {
            fprintf(stderr, "  Sender identified — sending pong\n");
        }

        /* Reflect this first ping immediately */
        mpcp_cal_pkt_t pong;
        memcpy(&pong, ping, sizeof(pong));
        pong.hdr.type = MPCP_TYPE_PONG;
        uint8_t wire_buf[512];
        size_t  wire_len = sizeof(pong);
        if (cfg->disguise_calibration) {
            wire_len = mpcp_disguise_wrap((const uint8_t *)&pong, sizeof(pong),
                                          wire_buf, sizeof(wire_buf),
                                          cfg->disguise_protocol);
            if (wire_len > 0)
                sendto(fd, wire_buf, wire_len, 0, (struct sockaddr *)&sender, slen);
        } else {
            sendto(fd, &pong, sizeof(pong), 0, (struct sockaddr *)&sender, slen);
        }
    }

    /* Phase 2: we have a live sender. Switch to idle timeout.
     * For slow_mode the sender gaps up to slow_mode_max_gap ms between pings,
     * so the idle timeout must exceed that or we'll bail out too early.
     * We also require at least cfg->ping_count_min pings before declaring
     * done - this prevents a single spurious packet from ending calibration. */
    {
        uint32_t idle_ms = 3000u; /* default: 3s idle = sender done */
        if (cfg->slow_mode && cfg->slow_mode_max_gap > 0)
            idle_ms = cfg->slow_mode_max_gap + 2000u; /* gap + 2s grace */
        struct timeval tv2;
        tv2.tv_sec  = (time_t)(idle_ms / 1000u);
        tv2.tv_usec = (suseconds_t)((idle_ms % 1000u) * 1000u);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    }

    /* Reflect pings for up to ping_count_max + grace.
     * Only exit on idle AFTER we have seen at least ping_count_min pings. */
    /* +30 head-room: +20 for loss/retransmit, +10 for mini_recal pings
     * that arrive after the main calibration burst finishes. */
    uint32_t max_pings = cfg->ping_count_max + 30;
    uint32_t reflected = 1; /* already counted the first one */

    while (reflected < max_pings) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&sender, &slen);
        if (n <= 0) {
            /* Idle timeout fired — sender has stopped pinging.
             * We are already in Phase 2 (got_first = true, nonce validated),
             * so silence means the sender genuinely finished calibrating.
             * Break immediately regardless of reflected count.
             * The old min_before_idle guard caused the receiver to loop
             * forever when packet loss meant reflected < ping_count_min. */
            break;
        }

        /* Optionally unwrap disguise */
        uint8_t pkt_buf[sizeof(mpcp_cal_pkt_t) + 64];
        size_t  pkt_len = (size_t)n;
        if (cfg->disguise_calibration) {
            pkt_len = mpcp_disguise_unwrap(buf, (size_t)n,
                                           pkt_buf, sizeof(pkt_buf),
                                           cfg->disguise_protocol);
            if (pkt_len == 0) continue;
        } else {
            if ((size_t)n > sizeof(pkt_buf)) continue;
            memcpy(pkt_buf, buf, (size_t)n);
        }

        if (pkt_len < sizeof(mpcp_cal_pkt_t)) continue;

        /* Validate magic + version */
        mpcp_cal_pkt_t *ping = (mpcp_cal_pkt_t *)pkt_buf;
        uint32_t magic;
        memcpy(&magic, &ping->hdr.magic, 4);
        if (ntohl(magic) != MPCP_MAGIC) continue;
        if (ping->hdr.version != MPCP_VERSION) continue;
        if (ping->hdr.type != MPCP_TYPE_PING) continue;

        /* Validate nonce_hint matches what we captured from the first ping.
         * This ensures all subsequent pings are from the same sender. */
        if (nonce_hint_out &&
            memcmp(ping->nonce_hint, nonce_hint_out, MPCP_NONCE_HINT_LEN) != 0)
            continue;

        /* Build pong: copy ping, flip type */
        mpcp_cal_pkt_t pong;
        memcpy(&pong, ping, sizeof(pong));
        pong.hdr.type = MPCP_TYPE_PONG;

        uint8_t wire_buf[512];
        size_t  wire_len = sizeof(pong);

        if (cfg->disguise_calibration) {
            wire_len = mpcp_disguise_wrap((const uint8_t *)&pong,
                                          sizeof(pong),
                                          wire_buf, sizeof(wire_buf),
                                          cfg->disguise_protocol);
            if (wire_len == 0) continue;
        } else {
            memcpy(wire_buf, &pong, sizeof(pong));
        }

        sendto(fd, wire_buf, wire_len, 0,
               (struct sockaddr *)&sender, slen);
        reflected++;
        /* Print progress every 10 pings to avoid per-ping write() jitter */
        if (reflected % 10 == 0 || reflected == 1) {
            fprintf(stderr, "\r  [%u pings reflected]   ", reflected);
            fflush(stderr);
        }
    }
    fprintf(stderr, "\r  %u pings reflected -- calibration done        \n", reflected);

    close(fd);
    return 0;
}


/* Expand leading ~/ to $HOME/ in path. Returns buf. */
static char *expand_tilde(const char *path, char *buf, size_t bufsz)
{
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char *home = getenv("HOME");
        if (!home) home = "/tmp";
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(buf, bufsz, "%s%s", home, path + 1);
#pragma GCC diagnostic pop
    } else {
        snprintf(buf, bufsz, "%s", path);
    }
    return buf;
}


/* =========================================================
 * --bench : loopback throughput benchmark
 *
 * Sends a generated file to 127.0.0.1 in two pthreads.
 * Reports MB/s and ms/chunk at the end.
 * ========================================================= */

typedef struct {
    mpcp_config_t    *cfg;
    mpcp_session_t   *sess;
    const char       *file_path;
    struct sockaddr_in peer;
    int               rc;
} bench_sender_arg_t;

typedef struct {
    mpcp_config_t       *cfg;
    mpcp_session_t      *sess;
    struct sockaddr_in   peer;   /* sender address for source validation */
    const char          *out_path;
    uint32_t             n_chunks;
    int                  rc;
} bench_receiver_arg_t;

static void *bench_sender_thread(void *arg)
{
    bench_sender_arg_t *a = (bench_sender_arg_t *)arg;
    a->rc = mpcp_sender_run(a->cfg, a->sess, &a->peer, a->file_path);
    return NULL;
}

static void *bench_receiver_thread(void *arg)
{
    bench_receiver_arg_t *a = (bench_receiver_arg_t *)arg;
    /* bench is always loopback; use the peer addr from bench args */
    a->rc = mpcp_receiver_run(a->cfg, a->sess, &a->peer, a->out_path, a->n_chunks);
    return NULL;
}

int run_bench(void)
{
    banner("Benchmark");
    printf("  Loopback transfer benchmark over 127.0.0.1\n");

    /* Generate a 4MB test file */
    char src_path[] = "/tmp/mpcp_bench_src.bin";
    char dst_path[] = "/tmp/mpcp_bench_dst.bin";
    size_t bench_size = 4u * 1024u * 1024u;

    {
        FILE *f = fopen(src_path, "wb");
        if (!f) { fprintf(stderr, "  error: cannot create %s\n", src_path); return 1; }
        uint8_t buf[4096];
        randombytes_buf(buf, sizeof(buf));
        for (size_t i = 0; i < bench_size / sizeof(buf); i++)
            fwrite(buf, 1, sizeof(buf), f);
        fclose(f);
    }
    printf("  Source: %s (%zu MB)\n", src_path, bench_size / (1024*1024));

    /* Config: fast profile, loopback */
    mpcp_config_t cfg;
    mpcp_config_defaults(&cfg);
    mpcp_profile_fast(&cfg);
    cfg.tripwire = false;  /* no tripwire on loopback */
    snprintf(cfg.psk, sizeof(cfg.psk), "bench-coral-tandem-velvet-sunrise");
    cfg.psk_len = strlen(cfg.psk);

    /* Shared session + nonce */
    mpcp_session_t sess_s, sess_r;
    memset(&sess_s, 0, sizeof(sess_s));
    memset(&sess_r, 0, sizeof(sess_r));
    randombytes_buf(sess_s.session_nonce, MPCP_SESSION_NONCE_LEN);
    memcpy(sess_r.session_nonce, sess_s.session_nonce, MPCP_SESSION_NONCE_LEN);

    /* Both sides derive the same master secret */
    if (mpcp_derive_master_secret(sess_s.session_nonce, NULL, 0,
                                   (const uint8_t *)cfg.psk, cfg.psk_len,
                                   sess_s.master_secret) != MPCP_OK ||
        mpcp_derive_master_secret(sess_r.session_nonce, NULL, 0,
                                   (const uint8_t *)cfg.psk, cfg.psk_len,
                                   sess_r.master_secret) != MPCP_OK) {
        fprintf(stderr, "  error: master secret derivation failed\n");
        return 1;
    }

    /* Pre-generate candidate key pair manually for bench */
    mpcp_candidates_t cands;
    memset(&cands, 0, sizeof(cands));
    if (mpcp_keygen_candidates(1, &cands) != MPCP_OK) {
        fprintf(stderr, "  error: keygen failed\n"); return 1;
    }
    if (mpcp_derive_session_key(sess_s.master_secret, cands.keys[0],
                                 sess_s.session_key) != MPCP_OK ||
        mpcp_derive_session_key(sess_r.master_secret, cands.keys[0],
                                 sess_r.session_key) != MPCP_OK) {
        fprintf(stderr, "  error: session key derivation failed\n");
        mpcp_keygen_candidates_free(&cands); return 1;
    }
    mpcp_keygen_candidates_free(&cands);

    /* Compute n_chunks */
    uint32_t n_chunks = 1;
    {
        size_t bound = ZSTD_compressBound(bench_size);
        uint8_t *raw = malloc(bench_size);
        if (raw) {
            FILE *f = fopen(src_path, "rb");
            if (f && fread(raw, 1, bench_size, f) == bench_size) {
                fclose(f);
                uint8_t *tmp = malloc(bound);
                if (tmp) {
                    size_t clen = ZSTD_compress(tmp, bound, raw, bench_size, 3);
                    bool sc = ZSTD_isError(clen) ||
                              ((double)clen / (double)bench_size > 0.95);
                    mpcp_chunk_plan_t plan;
                    memset(&plan, 0, sizeof(plan));
                    if (mpcp_chunker_plan(bench_size, cfg.chunk_pad_size, sc, &plan) == MPCP_OK)
                        n_chunks = plan.n_chunks;
                    free(tmp);
                }
            } else if (f) { fclose(f); }
            free(raw);
        }
    }
    printf("  Chunks: %u x %u KB\n", n_chunks, cfg.chunk_pad_size / 1024);

    /* Peer addr = loopback */
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family      = AF_INET;
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer.sin_port        = htons(cfg.port_base);

    bench_sender_arg_t   sarg = { &cfg, &sess_s, src_path, peer, 0 };
    bench_receiver_arg_t rarg = { &cfg, &sess_r, peer, dst_path, n_chunks, 0 };

    printf("  Starting loopback transfer...\n");
    uint64_t t0 = mpcp_now_ns();

    pthread_t ts, tr;
    pthread_create(&tr, NULL, bench_receiver_thread, &rarg);
    struct timespec tiny = { .tv_sec = 0, .tv_nsec = 10000000L };
    nanosleep(&tiny, NULL); /* give receiver a moment to bind */
    pthread_create(&ts, NULL, bench_sender_thread, &sarg);
    pthread_join(ts, NULL);
    pthread_join(tr, NULL);

    uint64_t elapsed_ns = mpcp_now_ns() - t0;
    double   elapsed_s  = (double)elapsed_ns / 1e9;
    double   mbps       = (double)bench_size / (1024.0 * 1024.0) / elapsed_s;
    double   ms_chunk   = (elapsed_s * 1000.0) / (double)n_chunks;

    if (sarg.rc != MPCP_OK || rarg.rc != MPCP_OK) {
        fprintf(stderr, "  Benchmark failed: sender=%d receiver=%d\n",
                sarg.rc, rarg.rc);
        remove(src_path); remove(dst_path);
        return 1;
    }

    /* Verify integrity */
    bool match = false;
    {
        FILE *fa = fopen(src_path, "rb");
        FILE *fb = fopen(dst_path, "rb");
        if (fa && fb) {
            uint8_t ba[4096], bb[4096];
            match = true;
            size_t na, nb;
            while ((na = fread(ba, 1, sizeof(ba), fa)) > 0) {
                nb = fread(bb, 1, sizeof(bb), fb);
                if (nb != na || memcmp(ba, bb, na) != 0) { match = false; break; }
            }
        }
        if (fa) fclose(fa);
        if (fb) fclose(fb);
    }

    remove(src_path); remove(dst_path);
    sodium_memzero(&sess_s, sizeof(sess_s));
    sodium_memzero(&sess_r, sizeof(sess_r));

    printf("\n  Results\n");
    printf("  -------\n");
    printf("  Transfer time : %.3f s\n", elapsed_s);
    printf("  Throughput    : %.1f MB/s\n", mbps);
    printf("  Per chunk     : %.1f ms\n", ms_chunk);
    printf("  Integrity     : %s\n\n", match ? "PASS - file matches" : "FAIL - mismatch!");
    return match ? 0 : 1;
}

/* =========================================================
 * --selftest : loopback integration test
 *
 * Like --bench but smaller and focused on correctness.
 * Runs ABOVE --test in the menu, exits 0 on pass.
 * ========================================================= */

int run_selftest(void)
{
    printf("\nMPCP Self-Test (loopback integration)\n");
    printf("======================================\n");

    char src[] = "/tmp/mpcp_selftest_src.bin";
    char dst[] = "/tmp/mpcp_selftest_dst.bin";
    size_t sz  = 512u * 1024u; /* 512 KB - small but covers multi-chunk */

    /* Write known pattern */
    {
        FILE *f = fopen(src, "wb");
        if (!f) { fprintf(stderr, "[selftest] cannot create src\n"); return 1; }
        for (size_t i = 0; i < sz; i++) fputc((int)(i & 0xFF), f);
        fclose(f);
    }

    mpcp_config_t cfg;
    mpcp_config_defaults(&cfg);
    mpcp_profile_fast(&cfg);
    cfg.tripwire = false;
    snprintf(cfg.psk, sizeof(cfg.psk), "selftest-coral-velvet-sunrise");
    cfg.psk_len = strlen(cfg.psk);

    mpcp_session_t ss, sr;
    memset(&ss, 0, sizeof(ss));
    memset(&sr, 0, sizeof(sr));
    randombytes_buf(ss.session_nonce, MPCP_SESSION_NONCE_LEN);
    memcpy(sr.session_nonce, ss.session_nonce, MPCP_SESSION_NONCE_LEN);

    if (mpcp_derive_master_secret(ss.session_nonce, NULL, 0,
                                   (const uint8_t *)cfg.psk, cfg.psk_len,
                                   ss.master_secret) != MPCP_OK ||
        mpcp_derive_master_secret(sr.session_nonce, NULL, 0,
                                   (const uint8_t *)cfg.psk, cfg.psk_len,
                                   sr.master_secret) != MPCP_OK) {
        fprintf(stderr, "[selftest] master secret failed\n"); return 1;
    }

    mpcp_candidates_t cands;
    memset(&cands, 0, sizeof(cands));
    mpcp_keygen_candidates(1, &cands);
    mpcp_derive_session_key(ss.master_secret, cands.keys[0], ss.session_key);
    mpcp_derive_session_key(sr.master_secret, cands.keys[0], sr.session_key);
    mpcp_keygen_candidates_free(&cands);

    /* n_chunks */
    uint32_t nc = 1;
    {
        uint8_t *raw = malloc(sz);
        if (raw) {
            FILE *f = fopen(src, "rb");
            if (f && fread(raw, 1, sz, f) == sz) {
                fclose(f);
                size_t bound = ZSTD_compressBound(sz);
                uint8_t *tmp = malloc(bound);
                if (tmp) {
                    size_t clen = ZSTD_compress(tmp, bound, raw, sz, 3);
                    bool sc = ZSTD_isError(clen) ||
                              ((double)clen / (double)sz > 0.95);
                    mpcp_chunk_plan_t plan; memset(&plan, 0, sizeof(plan));
                    if (mpcp_chunker_plan(sz, cfg.chunk_pad_size, sc, &plan) == MPCP_OK)
                        nc = plan.n_chunks;
                    free(tmp);
                }
            } else if (f) { fclose(f); }
            free(raw);
        }
    }

    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family      = AF_INET;
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer.sin_port        = htons(cfg.port_base);

    bench_sender_arg_t   sa = { &cfg, &ss, src, peer, 0 };
    bench_receiver_arg_t ra = { &cfg, &sr, peer, dst, nc, 0 };

    pthread_t ts, tr;
    pthread_create(&tr, NULL, bench_receiver_thread, &ra);
    struct timespec tiny = { .tv_sec = 0, .tv_nsec = 20000000L };
    nanosleep(&tiny, NULL);
    pthread_create(&ts, NULL, bench_sender_thread, &sa);
    pthread_join(ts, NULL);
    pthread_join(tr, NULL);

    int pass = 0;
    if (sa.rc == MPCP_OK && ra.rc == MPCP_OK) {
        /* Verify byte-for-byte */
        FILE *fa = fopen(src, "rb");
        FILE *fb = fopen(dst, "rb");
        bool ok = true;
        if (fa && fb) {
            uint8_t ba[4096], bb[4096];
            size_t na;
            while ((na = fread(ba, 1, sizeof(ba), fa)) > 0) {
                size_t nb = fread(bb, 1, sizeof(bb), fb);
                if (nb != na || memcmp(ba, bb, na) != 0) { ok = false; break; }
            }
            size_t leftover = fread(bb, 1, 1, fb);
            if (leftover > 0) ok = false; /* dst longer than src */
        } else { ok = false; }
        if (fa) fclose(fa);
        if (fb) fclose(fb);

        if (ok) {
            printf("  [PASS] Loopback transfer: file matches byte-for-byte\n");
            pass = 1;
        } else {
            printf("  [FAIL] Loopback transfer: file content mismatch\n");
        }
    } else {
        printf("  [FAIL] Transfer error: sender=%d receiver=%d\n", sa.rc, ra.rc);
    }

    remove(src); remove(dst);
    sodium_memzero(&ss, sizeof(ss));
    sodium_memzero(&sr, sizeof(sr));
    printf("  Selftest %s\n\n", pass ? "PASSED" : "FAILED");
    return pass ? 0 : 1;
}


/* =========================================================
 * Resume system
 *
 * On the receiver side, after each chunk is written to disk
 * we also append its seq index to a .mpcp_resume sidecar file.
 * Format: binary, 4 bytes per seq (big-endian uint32).
 *
 * On restart the receiver reads the sidecar, marks those seqs
 * as already received, and opens the output file in append mode
 * so new chunks continue from where they left off.
 *
 * The sender is told via transfer_info flags (bit 0) that the
 * receiver has a partial file.  For now the sender still sends
 * all chunks -- the receiver just silently discards already-done
 * seqs via the existing dedup bitmask.  This is safe and simple.
 *
 * Sidecar path: <out_path>.mpcp_resume
 * Deleted automatically on successful completion.
 * ========================================================= */

static void resume_path(const char *out_path, char *buf, size_t sz)
{
    snprintf(buf, sz, "%s.mpcp_resume", out_path);
}

/* Load resume state: returns number of seqs already done, fills bitmask.
 * Returns 0 if no resume file exists or it can't be read. */
uint32_t resume_load(const char *out_path,
                             bool       *done,   /* [max_chunks] */
                             uint32_t    max_chunks)
{
    char rpath[1200];
    resume_path(out_path, rpath, sizeof(rpath));

    FILE *f = fopen(rpath, "rb");
    if (!f) return 0;

    uint32_t count = 0;
    uint8_t  buf[4];
    while (fread(buf, 1, 4, f) == 4) {
        uint32_t seq = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                       ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
        if (seq < max_chunks && !done[seq]) {
            done[seq] = true;
            count++;
        }
    }
    fclose(f);
    return count;
}

/* Append one seq to the resume sidecar. Called after each chunk write. */
void resume_record(const char *out_path, uint32_t seq)
{
    char rpath[1200];
    resume_path(out_path, rpath, sizeof(rpath));

    FILE *f = fopen(rpath, "ab");
    if (!f) return;
    uint8_t buf[4] = {
        (uint8_t)(seq >> 24), (uint8_t)(seq >> 16),
        (uint8_t)(seq >>  8), (uint8_t)(seq      )
    };
    (void)fwrite(buf, 1, 4, f);
    fclose(f);
}

/* Delete the resume sidecar on clean completion. */
void resume_clear(const char *out_path)
{
    char rpath[1200];
    resume_path(out_path, rpath, sizeof(rpath));
    remove(rpath);
}

/* Check if a resume file exists for this output path. */
bool resume_exists(const char *out_path)
{
    char rpath[1200];
    resume_path(out_path, rpath, sizeof(rpath));
    struct stat st;
    return stat(rpath, &st) == 0;
}

int run_transfer(void)
{
    bool is_sender;

    /* ---- Mode ---- */
    banner("Mode");
    printf("  1) Send a file\n");
    printf("  2) Receive a file\n");
    char mode_buf[8];
    read_line("Select [1/2]: ", mode_buf, sizeof(mode_buf));
    is_sender = (mode_buf[0] == '1');
    printf("  -> %s mode\n", is_sender ? "Sender (PC2)" : "Receiver (PC1)");

    /* ---- Config + profile ---- */
    mpcp_config_t cfg;
    mpcp_config_defaults(&cfg);
    mpcp_config_load_default(&cfg);

    banner("Network profile");
    printf("  1) default  - wired LAN\n");
    printf("  2) wifi     - wireless / higher jitter\n");
    printf("  3) fast     - low-latency, pipelined\n");
    printf("  4) stealth  - slow, disguised, Ed25519 auth\n");
    printf("  5) internet - WAN / NAT traversal\n");
    char prof_buf[8];
    read_line("Profile [1-5, default=1]: ", prof_buf, sizeof(prof_buf));
    switch (prof_buf[0]) {
        case '2': mpcp_profile_wifi(&cfg);     printf("  -> wifi\n");     break;
        case '3': mpcp_profile_fast(&cfg);     printf("  -> fast\n");     break;
        case '4': mpcp_profile_stealth(&cfg);  printf("  -> stealth\n");  break;
        case '5': mpcp_profile_internet(&cfg); printf("  -> internet\n"); break;
        default:  mpcp_profile_default(&cfg);  printf("  -> default\n");  break;
    }

    /* ---- Auth / PSK ---- */
    banner("Authentication");
    if (cfg.auth_mode == MPCP_AUTH_ED25519) {
        printf("  Stealth mode — Ed25519 + PSK dual auth\n");
        printf("  Key directory: %s\n", cfg.auth_keydir);

        /* Check for existing keys */
        uint8_t _chk[32];
        uint8_t _sk64[64] = {0};
        bool has_sk   = (mpcp_ed25519_load_sk(cfg.auth_keydir, _sk64) == MPCP_OK ||
                         mpcp_ed25519_load_pk(cfg.auth_keydir, _chk) == MPCP_OK);
        sodium_memzero(_sk64, sizeof(_sk64));
        bool has_peer = (mpcp_ed25519_load_peer_pk(cfg.auth_keydir, _chk) == MPCP_OK);
        sodium_memzero(_chk, sizeof(_chk));

        if (!has_sk) {
            printf("  No keypair found in key directory.\n");
            if (ask_yn("  Generate new keypair?", true)) {
                if (mpcp_ed25519_keygen(cfg.auth_keydir) == MPCP_OK) {
                    printf("  -> Keypair written. Share %smpcp_ed25519.pk\n",
                           cfg.auth_keydir);
                    printf("     with your peer — they save it as mpcp_ed25519_peer.pk\n");
                    has_sk = true;
                } else {
                    mpcp_perror("ed25519 keygen", MPCP_ERR_CRYPTO);
                }
            }
        } else {
            printf("  Keypair: found\n");
        }

        if (!has_peer) {
            printf("  Peer public key: NOT FOUND\n");
            printf("  -> Ed25519 mutual auth disabled for this session.\n");
            printf("     Copy peer mpcp_ed25519.pk to %smpcp_ed25519_peer.pk\n",
                   cfg.auth_keydir);
            printf("     to enable it next time.\n");
            cfg.auth_mode = MPCP_AUTH_PSK;
        } else {
            printf("  Peer public key: found\n");
            if (g_ui_colour)
                printf("  %s" GLYPH_OK " Ed25519 mutual auth enabled.%s\n", C_LIME, C_RESET);
            else
                printf("  Ed25519 mutual auth enabled.\n");
        }
        printf("\n");

        /* Stealth calibration time warning for sender */
        if (cfg.slow_mode && is_sender) {
            uint32_t lo = cfg.ping_count_min * cfg.slow_mode_min_gap / 1000u;
            uint32_t hi = cfg.ping_count_max * cfg.slow_mode_max_gap / 1000u;
            if (g_ui_colour)
                printf("  %s⚠ Stealth calibration takes ~%u–%u seconds (slow pings by design).%s\n",
                       C_GOLD, lo, hi, C_RESET);
            else
                printf("  Note: stealth calibration takes ~%u-%u seconds.\n", lo, hi);
        }
    }

    if (cfg.auth_mode != MPCP_AUTH_ED25519 && !is_sender) {
        /* RECEIVER: generates the PSK and shares it out-of-band with the sender.
         * The receiver owns the session - they create the secret, the sender enters it. */
        printf("  You are the receiver. Generate a PSK and share it with the sender\n");
        printf("  over a secure channel (Signal, in person, etc.) before they start.\n\n");
        if (ask_yn("  Generate a PSK for me?", true)) {
            char generated[256];
            if (mpcp_generate_psk(generated, sizeof(generated)) == MPCP_OK) {
                printf("\n  Your PSK: %s\n", generated);
                printf("  ^^^ Share this with the sender NOW, then continue. ^^^\n\n");
                (void)ask_yn("  Done sharing? Continue", true);
                snprintf(cfg.psk, sizeof(cfg.psk), "%s", generated);
                cfg.psk_len = strlen(cfg.psk);
            } else {
                mpcp_perror("PSK generation", MPCP_ERR_CRYPTO);
                return 1;
            }
        } else {
            printf("  Enter the PSK you agreed on with the sender:\n");
            if (read_line("  PSK: ", cfg.psk, sizeof(cfg.psk)) != 0) return 1;
            cfg.psk_len = strlen(cfg.psk);
        }
        if (mpcp_config_check_psk(&cfg) != MPCP_OK) {
            mpcp_perror("PSK", MPCP_ERR_ENTROPY);
            return 1;
        }
        printf("  -> PSK accepted (%.0f bits)\n",
               mpcp_psk_entropy(cfg.psk, cfg.psk_len));
    } else {
        /* SENDER: enters the PSK they received from the receiver.
         * Never generates here - that would create a different key. */
        printf("  Enter the PSK the receiver gave you:\n");
        if (read_line("  PSK: ", cfg.psk, sizeof(cfg.psk)) != 0) return 1;
        cfg.psk_len = strlen(cfg.psk);
        if (mpcp_config_check_psk(&cfg) != MPCP_OK) {
            mpcp_perror("PSK", MPCP_ERR_ENTROPY);
            return 1;
        }
        printf("  -> PSK accepted (%.0f bits)\n",
               mpcp_psk_entropy(cfg.psk, cfg.psk_len));
    }

    /* ---- Peer address (sender needs receiver's IP; receiver doesn't need sender's) ---- */
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    if (is_sender) {
        banner("Receiver");
        if (resolve_peer(&peer_addr) != 0) return 1;
        /* Sender aims pings at receiver's port_base */
        peer_addr.sin_port = htons((uint16_t)cfg.port_base);
    }

    /* ---- File path ---- */
    char file_buf[1024];
    banner(is_sender ? "File to send" : "Save received file to");
    {
        char raw_path[1024];
        read_line(is_sender ? "  Path: " : "  Output path: ", raw_path, sizeof(raw_path));
        if (raw_path[0] == '\0') { fprintf(stderr, "  error [file]: no path entered\n"); return 1; }
        expand_tilde(raw_path, file_buf, sizeof(file_buf));
    }
    if (!is_sender) {
        struct stat _path_st;
        if (stat(file_buf, &_path_st) == 0 && S_ISDIR(_path_st.st_mode)) {
            fprintf(stderr, "  error [file]: %s is a directory - enter a full file path e.g. ~/Downloads/received.bin\n", file_buf);
            return 1;
        }
    }

    /* ---- Advanced (optional) ---- */
    banner("Advanced settings");
    if (ask_yn("  Adjust any settings?", false)) {
        char tmp[64];
        read_line("  Port base [default 10000]: ", tmp, sizeof(tmp));
        if (tmp[0] != '\0') cfg.port_base = (uint16_t)atoi(tmp);
        read_line("  Port range [default 55000]: ", tmp, sizeof(tmp));
        if (tmp[0] != '\0') cfg.port_range = (uint32_t)atol(tmp);
        read_line("  Pipeline depth [default 1]: ", tmp, sizeof(tmp));
        if (tmp[0] != '\0') cfg.pipeline_depth = (uint32_t)atoi(tmp);
        cfg.tripwire = ask_yn("  Enable tripwire?", true);
    }

    /* ---- Summary ---- */
    banner("Summary");
    printf("  Mode           : %s\n", is_sender ? "send (PC2)" : "receive (PC1)");
    printf("  Auth           : %s\n", cfg.auth_mode == MPCP_AUTH_ED25519 ? "Ed25519" : "PSK");
    printf("  Tripwire       : %s\n", cfg.tripwire ? "enabled" : "disabled");
    printf("  Ghost chunks   : %s\n", cfg.ghost_chunks_enabled ? "enabled" : "disabled");
    printf("  Port base/range: %u / %u\n", cfg.port_base, cfg.port_range);
    printf("  Pipeline depth : %u\n", cfg.pipeline_depth);
    printf("  %-15s: %s\n", is_sender ? "File" : "Output", file_buf);
    printf("\n");
    if (!ask_yn("Proceed?", true)) { printf("Aborted.\n"); return 0; }

    /* ===================================================================
     * SESSION SETUP
     *
     * Step 1: Generate a fresh session nonce (both sides independently).
     * The nonce is included in every HKDF derivation, binding all key
     * material to this specific session.
     * =================================================================== */
    mpcp_session_t    sess;
    memset(&sess, 0, sizeof(sess));
    /* Generate full 32-byte random session nonce.
     * All 32 bytes are transmitted to the receiver via the nonce_hint field
     * in calibration ping packets, so both sides derive identical nonces. */
    randombytes_buf(sess.session_nonce, MPCP_SESSION_NONCE_LEN);

    mpcp_candidates_t cands;
    memset(&cands, 0, sizeof(cands));

    int rc = MPCP_OK;
    spinner_t sp;

    if (is_sender) {
        /* Open firewall for inbound kex packets before calibration.
         * Key exchange (step 3) requires PC1 to send N candidate-key
         * packets TO the sender's derived kex ports. Without opening the
         * firewall here those inbound UDP packets are dropped and key
         * exchange times out. The receiver already calls fw_maybe_open at
         * the top of its block; we mirror that here for the sender. */
        fw_maybe_open(cfg.port_base, cfg.port_range);

        /* =================================================================
         * SENDER (PC2) FLOW
         *
         * 1. Calibrate link: send pings to PC1, collect RTTs.
         *    RTT samples feed directly into master secret derivation -
         *    this is the "timing entropy" source from spec S7.4.
         * 2. Derive master secret from: timing + PSK + OS random + ts.
         * 3. Key exchange PC2: receive N candidate keys from PC1,
         *    select one using constant-time blind selection, return N-1.
         * 4. Send file.
         * ================================================================= */

        /* Step 1: Calibrate - collect RTT samples */
        banner("Calibrating link");
        printf("  Sending pings to receiver at %s:%u ...\n",
               inet_ntoa(peer_addr.sin_addr), cfg.port_base);
        spinner_start(&sp, "  Measuring RTT");

        double   *rtt_samples = NULL;
        uint32_t  rtt_count   = 0;
        mpcp_rtt_result_t rtt;
        memset(&rtt, 0, sizeof(rtt));

        rc = mpcp_calibrate_collect_samples(&cfg, &sess, &peer_addr,
                                            &rtt_samples, &rtt_count, &rtt);
        spinner_stop(&sp, rc == MPCP_OK);
        if (rc != MPCP_OK) { mpcp_perror("calibration", rc); return 1; }
        fprintf(stderr, "\n"); /* end the running ping/pong line */
        printf("  RTT: %.1f ms  std: %.1f ms  catch window: %.0f ms  samples: %u\n",
               rtt.baseline_mean, rtt.baseline_std, rtt.catch_window, rtt_count);

        /* Step 2: Derive master secret from timing entropy + PSK + OS RNG + ts */
        rc = mpcp_derive_master_secret(sess.session_nonce,
                                       rtt_samples, rtt_count,
                                       (const uint8_t *)cfg.psk, cfg.psk_len,
                                       sess.master_secret);
        free(rtt_samples);
        if (rc != MPCP_OK) { mpcp_perror("master secret", rc); return 1; }

        /* Step 3: Key exchange - PC2 receives N keys from PC1, picks one */
        banner("Key exchange");
        spinner_start(&sp, "  Exchanging keys");
        rc = mpcp_exchange_pc2(&cfg, &sess, &peer_addr);
        spinner_stop(&sp, rc == MPCP_OK);
        if (rc != MPCP_OK) { mpcp_perror("key exchange", rc); return 1; }
        printf("  Session key established.\n");

        /* Step 3b: Tell receiver how many chunks to expect.
         * mpcp_sender_run computes n_chunks internally; we need to
         * compute it here too so we can send it before the transfer. */
        {
            /* Compute EXACT n_chunks using the same logic as sender_run:
             * fully compress the file, then plan from the compressed size.
             * An estimate would cause ghost_map and keystream mismatches. */
            struct stat _st;
            if (stat(file_buf, &_st) == 0 && _st.st_size > 0) {
                size_t fsize = (size_t)_st.st_size;
                size_t bound = ZSTD_compressBound(fsize);
                uint8_t *raw = malloc(fsize);
                uint32_t exact_chunks = 1;
                uint8_t  xfer_skip_flag = 0; /* MPCP_FLAG_SKIP_COMPRESSION if file incompressible */
                if (raw) {
                    FILE *pf = fopen(file_buf, "rb");
                    if (pf && fread(raw, 1, fsize, pf) == fsize) {
                        fclose(pf);
                        uint8_t *tmp = malloc(bound);
                        if (tmp) {
                            size_t clen = ZSTD_compress(tmp, bound, raw, fsize, cfg.zstd_level);
                            /* Match sender_run's compressibility threshold:
                             * ratio > 0.95 → incompressible → use original fsize.
                             * ZSTD_isError alone misses cases where ZSTD succeeds
                             * but output is LARGER than input (e.g. JPEG/PNG),
                             * which would cause n_chunks to diverge from sender_run. */
                            bool zstd_err = (ZSTD_isError(clen) != 0);
                            double ratio  = zstd_err ? 1.0 : (double)clen / (double)fsize;
                            bool   sc     = zstd_err || (ratio > 0.95);
                            if (sc) xfer_skip_flag = MPCP_FLAG_SKIP_COMPRESSION;
                            /* Plan from fsize: sender_run always reads raw bytes
                             * from the original file in file_size/n_chunks pieces. */
                            mpcp_chunk_plan_t plan;
                            memset(&plan, 0, sizeof(plan));
                            if (mpcp_chunker_plan(fsize, cfg.chunk_pad_size, sc, &plan) == MPCP_OK)
                                exact_chunks = plan.n_chunks;
                            free(tmp);
                        }
                    } else if (pf) { fclose(pf); }
                    free(raw);
                }
                (void)transfer_info_send(&sess, &cfg, &peer_addr,
                                         exact_chunks, xfer_skip_flag);
            }
        }

        /* Step 4: Send */
        banner("Sending");
        /* We can't get acks_received from outside sender_run without refactoring
         * the API, so we use a simple time-based spinner for now and show
         * final stats after. The progress bar is used on the receiver side
         * where we can observe chunk_store fills directly. */
        spinner_start(&sp, "  Transferring");
        rc = mpcp_sender_run(&cfg, &sess, &peer_addr, file_buf);
        spinner_stop(&sp, rc == MPCP_OK);
        if (rc == MPCP_OK) printf("  Transfer complete.\n");
        else mpcp_perror("send", rc);

    } else {
        /* =================================================================
         * RECEIVER (PC1) FLOW
         *
         * 1. Reflect pongs: listen on port_base, mirror every ping back.
         *    This lets PC2 measure RTT. PC1 has no RTT samples of its
         *    own - timing entropy is one-sided by design (spec S7.4).
         * 2. Derive master secret from PSK + OS random + ts (no RTT).
         *    Both sides converge on the same master secret because the
         *    PSK and nonce are shared and getrandom()+ts give independent
         *    entropy that doesn't need to match.
         * 3. Key exchange PC1: generate N candidate keys, send all N to
         *    PC2, wait to receive N-1 back, identify the selected key by
         *    set subtraction.
         * 4. Receive file.
         * ================================================================= */

        /* Step 1: Reflect pings as pongs so sender can calibrate */
        fw_maybe_open(cfg.port_base, cfg.port_range);
        banner("Waiting for sender");
        /* Show receiver's own IPs using getifaddrs (reads kernel interface list
         * directly — immune to /etc/hosts misconfigurations that make
         * gethostname/getaddrinfo return 127.0.0.1 or Tailscale/VPN IPs). */
        {
            struct ifaddrs *ifap, *ifa;
            if (getifaddrs(&ifap) == 0) {
                printf("  Your IP addresses (give one of these to the sender):\n");
                bool found_any = false;
                for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr) continue;
                    if (ifa->ifa_addr->sa_family != AF_INET) continue;
                    struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                    char ipstr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sa->sin_addr, ipstr, sizeof(ipstr));
                    /* Skip loopback and link-local (169.254.x.x) */
                    uint32_t ip = ntohl(sa->sin_addr.s_addr);
                    if ((ip >> 24) == 127) continue;           /* 127.x.x.x */
                    if ((ip >> 16) == 0xA9FE) continue;        /* 169.254.x.x */
                    if (g_ui_colour)
                        printf("    %s%s%s  %s(%s)%s\n",
                               C_PLUM, ipstr, C_RESET,
                               C_GREY, ifa->ifa_name, C_RESET);
                    else
                        printf("    %-16s  (%s)\n", ipstr, ifa->ifa_name);
                    found_any = true;
                }
                if (!found_any)
                    printf("    (no non-loopback interfaces found — check network)\n");
                freeifaddrs(ifap);
            }
        }
        printf("  Listening for calibration pings on port %u ...\n", cfg.port_base);
        printf("  (Start the sender now - they need your IP above and port %u)\n", cfg.port_base);
        /* pong_server will fill sender_addr with the sender's IP:port
         * and nonce_hint with the first 16 bytes of the sender's nonce.
         * We then adopt the sender's nonce so both sides derive the same
         * master secret. */
        struct sockaddr_in sender_addr;
        memset(&sender_addr, 0, sizeof(sender_addr));
        uint8_t nonce_hint[MPCP_SESSION_NONCE_LEN];
        memset(nonce_hint, 0, sizeof(nonce_hint));

        spinner_start(&sp, "  Reflecting pings");
        int pong_rc = pong_server(&cfg, &sender_addr, nonce_hint, false);
        spinner_stop(&sp, pong_rc == 0);
        if (pong_rc != 0) {
            fw_cleanup();
            fprintf(stderr, "  error [calibration]: failed to bind port %u - is another process using it?\n", cfg.port_base);
            return 1;
        }

        /* Adopt sender's full nonce (all 32 bytes transmitted via nonce_hint). */
        memcpy(sess.session_nonce, nonce_hint, MPCP_SESSION_NONCE_LEN);

        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip));
        printf("  Calibration phase complete. Sender: %s\n", sender_ip);

        /* Step 2: Derive master secret (no RTT samples on receiver side) */
        rc = mpcp_derive_master_secret(sess.session_nonce,
                                       NULL, 0,
                                       (const uint8_t *)cfg.psk, cfg.psk_len,
                                       sess.master_secret);
        if (rc != MPCP_OK) { mpcp_perror("master secret", rc); return 1; }

        /* Step 3: Key exchange - PC1 generates N keys, sends them, finds selected.
         * sender_addr is the peer address learned from calibration pings. */
        banner("Key exchange");
        spinner_start(&sp, "  Exchanging keys");
        rc = mpcp_exchange_pc1(&cfg, &sess, &sender_addr, &cands);
        spinner_stop(&sp, rc == MPCP_OK);
        if (rc != MPCP_OK) { mpcp_perror("key exchange", rc); return 1; }
        printf("  Session key established.\n");

        /* Step 3b: Receive transfer info so we know n_chunks */
        uint32_t n_chunks = 0;
        uint8_t  xfer_flags = 0;
        spinner_start(&sp, "  Awaiting transfer info");
        rc = transfer_info_recv(&sess, &cfg, &n_chunks, &xfer_flags);
        spinner_stop(&sp, rc == MPCP_OK);
        if (rc != MPCP_OK) {
            mpcp_perror("transfer info", rc);
            fprintf(stderr, "  hint:  make sure the sender started and both sides use the same PSK\n");
            return 1;
        }
        printf("  Expecting %u chunks.\n", n_chunks);

        /* Check for partial resume state */
        if (resume_exists(file_buf)) {
            bool *done_map = calloc(n_chunks, sizeof(bool));
            uint32_t already = 0;
            if (done_map) {
                already = resume_load(file_buf, done_map, n_chunks);
                free(done_map);
            }
            if (already > 0) {
                printf("  Resume: found %u/%u chunks already received\n",
                       already, n_chunks);
                if (!ask_yn("  Resume from previous partial transfer?", true)) {
                    resume_clear(file_buf);
                    printf("  Starting fresh.\n");
                } else {
                    printf("  Resuming - %u chunks remaining\n", n_chunks - already);
                }
            }
        }

        /* Validate output path is a file, not a directory */
        {
            struct stat _st;
            if (stat(file_buf, &_st) == 0 && S_ISDIR(_st.st_mode)) {
                fprintf(stderr, "  error [file]: output path is a directory - please specify a full file path\n");
                return 1;
            }
        }

        /* Apply skip_compression from sender so writer doesn't try to
         * ZSTD_decompress raw bytes (e.g. JPEG, PNG, already-compressed files). */
        sess.skip_compression = (xfer_flags & MPCP_FLAG_SKIP_COMPRESSION) != 0;

        /* Step 4: Receive with live progress bar */
        banner("Receiving");
        {
            uint32_t recv_n = n_chunks;
            printf("  Expecting %u data chunks\n", recv_n);
            spinner_start(&sp, "  Receiving");
            rc = mpcp_receiver_run(&cfg, &sess, &sender_addr, file_buf, recv_n);
            spinner_stop(&sp, rc == MPCP_OK);
        }
        if (rc == MPCP_OK) {
            printf("  File saved to: %s\n", file_buf);
            resume_clear(file_buf);  /* belt-and-suspenders */
        } else {
            mpcp_perror("receive", rc);
        }
    }

    sodium_memzero(&sess, sizeof(sess));
    sodium_memzero(cfg.psk, sizeof(cfg.psk));
    fw_cleanup();  /* close any firewall rules opened for this session */
    return (rc == MPCP_OK) ? 0 : 1;
}

/* =========================================================
 * Main menu
 * ========================================================= */


/* =========================================================
 * Server / Listen mode  (menu option 5)
 *
 * Sits on port_base waiting for incoming senders.
 * Each time a sender calibrates, prompts operator to accept/reject.
 * If accepted, runs a full receive session then loops back to listen.
 * ========================================================= */
int run_listen_once(void)
{
    banner("Listen mode");
    if (g_ui_colour)
        printf("  %sWaiting for an incoming sender. Press Ctrl-C to stop.%s\n",
               C_GREY, C_RESET);
    else
        printf("  Waiting for incoming sender (Ctrl-C to stop)\n");

    mpcp_config_t cfg;
    mpcp_config_defaults(&cfg);
    mpcp_profile_default(&cfg);
    cfg.tripwire = false;   /* operator is watching; skip automated abort */

    /* Ask for output directory */
    char outdir[512] = {0};
    read_line("  Save received files to directory: ", outdir, sizeof(outdir));
    if (outdir[0] == ' ') snprintf(outdir, sizeof(outdir), "%s", getenv("HOME") ? getenv("HOME") : ".");

    /* No PSK pre-set — sender will negotiate one */
    printf("  Listening on port %u\n", cfg.port_base);
    printf("  Files will be saved to: %s\n", outdir);

    fw_maybe_open(cfg.port_base, cfg.port_range);

    /* Show IPs */
    {
        struct ifaddrs *ifap, *ifa;
        if (getifaddrs(&ifap) == 0) {
            printf("  Your IP addresses:\n");
            for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                uint32_t ip = ntohl(sa->sin_addr.s_addr);
                if ((ip >> 24) == 127 || (ip >> 16) == 0xA9FE) continue;
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, ipstr, sizeof(ipstr));
                if (g_ui_colour)
                    printf("    %s%s%s  %s(%s)%s\n", C_PLUM, ipstr, C_RESET,
                           C_GREY, ifa->ifa_name, C_RESET);
                else
                    printf("    %-16s  (%s)\n", ipstr, ifa->ifa_name);
            }
            freeifaddrs(ifap);
        }
    }

    for (;;) {
        struct sockaddr_in sender_addr;
        memset(&sender_addr, 0, sizeof(sender_addr));
        uint8_t nonce_hint[MPCP_SESSION_NONCE_LEN];
        memset(nonce_hint, 0, sizeof(nonce_hint));

        int pong_rc = pong_server(&cfg, &sender_addr, nonce_hint, true);
        if (pong_rc == -2) {
            /* Rejected — loop back and wait for next sender */
            printf("  Listening again...\n");
            continue;
        }
        if (pong_rc != 0) {
            fprintf(stderr, "  error: calibration failed\n");
            break;
        }

        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip));
        printf("  Accepted sender: %s\n", sender_ip);

        /* Enter PSK for this session */
        banner("Authentication");
        printf("  Enter the PSK the sender gives you:\n");
        if (read_line("  PSK: ", cfg.psk, sizeof(cfg.psk)) != 0) break;
        cfg.psk_len = strlen(cfg.psk);
        if (mpcp_config_check_psk(&cfg) != MPCP_OK) {
            mpcp_perror("PSK", MPCP_ERR_ENTROPY);
            continue;
        }

        /* Build output path: outdir/sender_ip_timestamp.bin */
        char out_path[768];
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm);
        snprintf(out_path, sizeof(out_path), "%s/%s_%s.bin", outdir, sender_ip, ts);
        printf("  Saving to: %s\n", out_path);

        /* Full session */
        mpcp_session_t sess;
        memset(&sess, 0, sizeof(sess));
        memcpy(sess.session_nonce, nonce_hint, MPCP_SESSION_NONCE_LEN);

        if (mpcp_derive_master_secret(sess.session_nonce, NULL, 0,
                                       (const uint8_t *)cfg.psk, cfg.psk_len,
                                       sess.master_secret) != MPCP_OK) {
            mpcp_perror("master secret", MPCP_ERR_CRYPTO);
            continue;
        }

        mpcp_candidates_t cands;
        memset(&cands, 0, sizeof(cands));
        banner("Key exchange");
        spinner_t sp;
        spinner_start(&sp, "  Exchanging keys");
        int rc = mpcp_exchange_pc1(&cfg, &sess, &sender_addr, &cands);
        spinner_stop(&sp, rc == MPCP_OK);
        if (rc != MPCP_OK) { mpcp_perror("key exchange", rc); continue; }
        printf("  Session key established.\n");

        uint32_t n_chunks = 0;
        uint8_t  xfer_flags = 0;
        spinner_start(&sp, "  Awaiting transfer info");
        rc = transfer_info_recv(&sess, &cfg, &n_chunks, &xfer_flags);
        spinner_stop(&sp, rc == MPCP_OK);
        if (rc != MPCP_OK) { mpcp_perror("transfer info", rc); continue; }
        sess.skip_compression = (xfer_flags & MPCP_FLAG_SKIP_COMPRESSION) != 0;
        printf("  Expecting %u chunks.\n", n_chunks);

        banner("Receiving");
        printf("  Expecting %u data chunks\n", n_chunks);
        spinner_start(&sp, "  Receiving");
        rc = mpcp_receiver_run(&cfg, &sess, &sender_addr, out_path, n_chunks);
        spinner_stop(&sp, rc == MPCP_OK);
        if (rc == MPCP_OK) {
            if (g_ui_colour)
                printf("  %s" GLYPH_OK " File saved: %s%s\n", C_LIME, out_path, C_RESET);
            else
                printf("  File saved: %s\n", out_path);
        } else {
            mpcp_perror("receive", rc);
        }

        sodium_memzero(&sess, sizeof(sess));
        sodium_memzero(cfg.psk, sizeof(cfg.psk));
        cfg.psk_len = 0;

        printf("\n");
        if (!ask_yn("  Wait for another sender?", true)) break;
        printf("  Listening again...\n");
    }

    fw_cleanup();
    return 0;
}
