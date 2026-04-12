# ☾ ClockWork ☽

### 🌌 Nightbound synchronization for ClockWork 🌌

...

**Protocol** · ClockWork v0.5

**Project** · ClockWork

...

ClockWork is the tooling and reference implementation built around **ClockWork** — the **Multi-Port Catch Protocol**.

...

**ClockWork** is the protocol.

**ClockWork** is the implementation and tooling built around it.

...

- ClockWork defines behavior, timing, and cryptographic structure
- ClockWork executes and exposes that system

...

gcc -std=c11 -D_GNU_SOURCE -O2 ClockWork.c -o clockwork -lsodium -lzstd -lm -lpthread

gcc -std=c11 -D_GNU_SOURCE -O2 ClockWork_plain.c -o clockwork -lsodium -lzstd -lm -lpthread

...

make clockwork-plain

...

./clockwork --test

./clockwork --selftest

./clockwork --bench

...

ClockWork is asymmetric — **the receiver starts first.**

...

./clockwork  →  1) Send / Receive  →  2) Receive a file

./clockwork  →  1) Send / Receive  →  1) Send a file

...

./clockwork                # interactive menu

./clockwork --test         # unit tests only (no network)

./clockwork --selftest     # unit tests + loopback integration

./clockwork --bench        # loopback throughput benchmark

./clockwork -v             # verbose — writes session log to ~/.config/clockwork/

...

./clockwork  →  profile 4 (stealth)  →  Generate new keypair: Y

Writes to `~/.config/clockwork/keys/`:

- `clockwork_ed25519.sk` — your secret key (mode 0600, never share)
- `clockwork_ed25519.pk` — your public key (share with peer)

...

~/.config/clockwork/keys/clockwork_ed25519_peer.pk

If no peer key is found, ClockWork falls back to PSK-only and tells you exactly what to copy where.

...

ClockWork detects `firewalld`, `ufw`, or `iptables` and offers to open ports automatically (one `sudo` prompt). Ports are closed when the session ends.

...

| `~/.config/clockwork/contacts` | Saved peer aliases |
| `~/.config/clockwork/keys/` | Ed25519 keypair (stealth only) |
| `~/.config/clockwork/canary.log` | Tripwire abort events |
| `~/.config/clockwork/clockwork-log-*.txt` | Verbose session logs (`-v`) |
| `<output>.clockwork_resume` | Partial transfer state — deleted on success |

...

ClockWork.c          ← single-file colour build (amalgam)

ClockWork_plain.c    ← single-file headless build (amalgam)

...

│   ├── clockwork.h          all types, constants, prototypes, colour macros

...

- label deviations from the ClockWork spec as **Unverified Implementation**

...

Full protocol specification: `ClockWork_v0.5_FINAL_PowerTea-2.pdf`