<div align="center">

<br>

# ☾ AethroSync ☽
### 🌌 Nightbound synchronization for MPCP 🌌

<sub><em>built under starlight for precision, privacy, and event-correlation research</em></sub>

<br>

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-5a6cff.svg?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
![Language](https://img.shields.io/badge/language-C11-8a6fff.svg?style=for-the-badge)
![Tests](https://img.shields.io/badge/tests-183%2F183-4a9fff.svg?style=for-the-badge)

<br>

༺═⋆════════════════════════════⋆═༻  
   ☾  C O R E   I D E N T I T Y  ☽  
༺═⋆════════════════════════════⋆═༻  

**Protocol** · MPCP v0.5  
**Project** · AethroSync  
**Maintainer** · PowerTea-2  

</div>

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  O V E R V I E W  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

AethroSync is the tooling and reference implementation built around **MPCP** — the **Multi-Port Catch Protocol**.

It is engineered for:

- ✦ **Z-score timing windows** and real-time event correlation  
- ✦ **XChaCha20-Poly1305 + HKDF** key derivation from shared nonce + PSK  
- ✦ **Dynamic port-hopping** with ghost chunks for traffic blending  
- ✦ **Tripwire detection** using z-score and χ² loss-pattern analysis  
- ✦ **Oblivious key exchange** — neither side knows which candidate key was selected until after session derivation  
- ✦ **Per-chunk compression** with compressibility detection — JPEGs, PNGs and already-compressed files skip ZSTD automatically  
- ✦ **Traffic disguise** — stealth profile wraps calibration pings as DNS or NTP packets  
- ✦ **Zero-copy pipeline** with `SCHED_FIFO` timing thread  

> *For researchers who require something that simply does not leak.*

**MPCP** is the protocol.  
**AethroSync** is the implementation and tooling built around it.

- MPCP defines behavior, timing, and cryptographic structure  
- AethroSync executes and exposes that system  

This separation ensures the protocol remains independently verifiable.

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  I N S T A L L A T I O N  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

<details>
<summary><b>✨ Nix (fully reproducible)</b></summary>

```bash
nix-shell -p libsodium zstd gcc gnumake
```

</details>

<details>
<summary><b>🐧 Debian / Ubuntu</b></summary>

```bash
sudo apt install libsodium-dev libzstd-dev gcc
```

</details>

<details>
<summary><b>🎩 Fedora / RHEL</b></summary>

```bash
sudo dnf install libsodium-devel libzstd-devel gcc
```

</details>

<details>
<summary><b>🏹 Arch Linux</b></summary>

```bash
sudo pacman -S libsodium zstd gcc
```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
brew install libsodium zstd
```

</details>

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  C O M P I L A T I O N  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

**Single-file builds** (simplest — grab one file and go):

```bash
# Colour terminal build — purple UI, animations, braille spinner
gcc -std=c11 -D_GNU_SOURCE -O2 AethroSync.c -o mpcp -lsodium -lzstd -lm -lpthread

# Headless / server build — plain ASCII, works on any TTY or over SSH
gcc -std=c11 -D_GNU_SOURCE -O2 AethroSync_plain.c -o mpcp -lsodium -lzstd -lm -lpthread
```

**Multi-file build** (from the `split/` folder — easier to navigate and extend):

```bash
cd split/
make              # colour build  →  ./mpcp
make mpcp-plain   # headless build →  ./mpcp-plain
```

The binary is fully self-contained. Copy it anywhere.

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  V E R I F Y  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

```bash
./mpcp --test        # 183 unit tests  (~1 second)
./mpcp --selftest    # loopback byte-for-byte integrity check
./mpcp --bench       # 4 MB loopback throughput benchmark
```

Expected output:
```
Results: 125/125 passed
Results: 58/58 passed
[PASS] Loopback transfer: file matches byte-for-byte
Selftest PASSED
Throughput: ~2–4 MB/s
```

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  U S A G E  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

MPCP is asymmetric — **the receiver starts first.**

**Receiver (PC1):**
```
./mpcp  →  1) Send / Receive  →  2) Receive a file
→  Choose a profile  →  Generate a PSK  →  Share PSK + your IP with sender
```

**Sender (PC2):**
```
./mpcp  →  1) Send / Receive  →  1) Send a file
→  Same profile  →  Enter PSK  →  Enter receiver IP  →  Choose file
```

The transfer negotiates keys, calibrates the link, and begins automatically.

<br>

### Profiles

| Profile | Use case | Notes |
|---|---|---|
| `default` | Wired LAN | Fast calibration, full stealth |
| `wifi` | Wireless / higher jitter | Wider catch window |
| `fast` | Low-latency links | Reduced ghost chunks, deeper pipeline |
| `stealth` | Maximum disguise | DNS-wrapped pings, 2–18 min calibration by design |
| `internet` | WAN / cross-network | High-latency tolerances |

> **Stealth note:** calibration takes 2–18 minutes intentionally — slow pings blend into normal DNS traffic patterns. Both sides must wait.

<br>

### Server / Listen mode (option 5)

Sits on `port_base` indefinitely. Each time a sender calibrates it prompts:

```
Incoming connection from 192.168.1.42 — Accept? [Y/n]
```

Files are auto-named `ip_timestamp.bin` in a directory you specify at startup. Loop back to listening after each transfer.

<br>

### Command-line flags

```bash
./mpcp                # interactive menu
./mpcp --test         # unit tests only (no network)
./mpcp --selftest     # unit tests + loopback integration
./mpcp --bench        # loopback throughput benchmark
./mpcp -v             # verbose — writes session log to ~/.config/mpcp/
```

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  E d 2 5 5 1 9   A U T H  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

Stealth profile supports Ed25519 mutual authentication on top of the PSK.

**Setup (once per machine):**
```
./mpcp  →  profile 4 (stealth)  →  Generate new keypair: Y
```

Writes to `~/.config/mpcp/keys/`:
- `mpcp_ed25519.sk` — your secret key (mode 0600, never share)
- `mpcp_ed25519.pk` — your public key (share with peer)

**Exchange keys:**
```bash
# Peer saves your .pk as:
~/.config/mpcp/keys/mpcp_ed25519_peer.pk
```

If no peer key is found, AethroSync falls back to PSK-only and tells you exactly what to copy where.

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  F I R E W A L L  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

AethroSync detects `firewalld`, `ufw`, or `iptables` and offers to open ports automatically (one `sudo` prompt). Ports are closed when the session ends.

Manual override if needed:
```bash
# firewalld
sudo firewall-cmd --add-port=10000-65000/udp

# ufw
sudo ufw allow 10000:65000/udp

# iptables
sudo iptables -I INPUT 1 -p udp --dport 10000:65000 -j ACCEPT
```

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  F I L E S  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

| Path | Contents |
|---|---|
| `~/.config/mpcp/contacts` | Saved peer aliases |
| `~/.config/mpcp/keys/` | Ed25519 keypair (stealth only) |
| `~/.config/mpcp/canary.log` | Tripwire abort events |
| `~/.config/mpcp/mpcp-log-*.txt` | Verbose session logs (`-v`) |
| `<output>.mpcp_resume` | Partial transfer state — deleted on success |

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  P R O J E C T   L A Y O U T  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

```
AethroSync.c          ← single-file colour build (amalgam)
AethroSync_plain.c    ← single-file headless build (amalgam)
split/
├── Makefile
├── include/
│   ├── mpcp.h          all types, constants, prototypes, colour macros
│   ├── ui.h            UI animation functions
│   └── test_helpers.h  shared test macros
├── src/
│   ├── crypto.c        HKDF, AEAD, Ed25519, key derivation
│   ├── config.c        config struct, profiles, parser
│   ├── calibrate.c     ping/pong, RTT pipeline
│   ├── disguise.c      DNS/NTP traffic disguise
│   ├── keygen.c        candidate key generation
│   ├── exchange.c      PC1/PC2 key exchange
│   ├── tripwire.c      chi-squared loss detector
│   ├── chunker.c       chunk planning, compression, ghost generation
│   ├── nat.c           NAT traversal
│   ├── pipeline.c      ring buffers, sender/receiver threads
│   ├── cli.c           contacts, bench, selftest, listen, transfer
│   └── main.c          int main()
└── tests/
    ├── test_core.c     Phase 1+2 unit tests (125 checks)
    └── test_phase3.c   Phase 3 unit tests (58 checks)
```

<br>

༺═══════════════◈═══════════════༻  
   ⋆₊⁺  L E G A L  ⁺₊⋆  
༺═══════════════◈═══════════════༻  

Licensed under the **GNU Affero General Public License v3.0**

**Moral Rights** asserted by PowerTea-2 under EU copyright law

Any derivative must:

- clearly mark itself as a fork  
- preserve the **Founding Architect** credit in all UI elements  
- label deviations from the MPCP spec as **Unverified Implementation**  

See `NOTICE` and `LICENSE` for full terms.

Full protocol specification: `MPCP_v0.5_FINAL_PowerTea-2.pdf`

> Security note — research and educational use. No warranty.

<br>

<div align="center">

༺═⋆════════════════════════════⋆═༻  
        ☾ carved under cold starlight ☽  
             **PowerTea-2**  
༺═⋆════════════════════════════⋆═༻  

</div>
