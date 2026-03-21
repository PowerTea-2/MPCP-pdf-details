<div align="center">

.  * .  . * * .        .        .   * ..
# ☾ ⋆⁺₊⋆ MPCP ⋆⁺₊⋆ ☾
### 🌌 Multi-Port Catch Protocol 🌌
.  * .  . * * .        .        .   * ..

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**v0.5** — *A cryptographically sealed, multi-port catch protocol for privacy research and event-correlation analysis.*

༺ ═════════════════════ ⋆⋅☆⋅⋆ ═════════════════════ ༻

**Founding Architect** — PowerTea-2 <br>
**Protocol Specification** — v0.5

</div>

## ✨ Overview

MPCP is a high-assurance UDP protocol engineered for:

✦ **Z-score timing windows** and real-time event correlation  
✦ **XChaCha20-Poly1305 + HKDF** key material derived from shared nonce + PSK  
✦ **Dynamic port-hopping** with ghost chunks for traffic blending  
✦ **Tripwire detection** (z-score + χ² loss-pattern analysis)  
✦ **Zero-copy pipeline** with `SCHED_FIFO` timing thread  

> *Built for researchers who need something that simply **does not leak**.*

༺ ════════════════════════ ☾ ★ ☽ ════════════════════════ ༻

## 🌠 Dependencies & Installation

<details>
<summary><b>✨ Nix (Recommended — fully reproducible)</b></summary>


nix-shell -p libsodium libzstd gcc gnumake --run "bash"

</details>

<details>
<summary><b>🐧 Debian / Ubuntu</b></summary>


sudo apt install libsodium-dev libzstd-dev

</details>

<details>
<summary><b>🎩 Fedora / RHEL</b></summary>


sudo dnf install libsodium-devel libzstd-devel

</details>

<details>
<summary><b>🏹 Arch Linux</b></summary>

sudo pacman -S libsodium zstd

</details>

<details>
<summary><b>🍎 macOS</b></summary>


brew install libsodium zstd

</details>

༺ ════════════════════════ ☾ ★ ☽ ════════════════════════ ༻
⚡ Compilation

Once your dependencies are sparkling, compile with:


gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O2 \
    mpcp_fixed.c -o mpcp -lsodium -lzstd -lm -lpthread

༺ ════════════════════════ ☾ ★ ☽ ════════════════════════ ༻
📜 Legal & Moral Rights

Licensed under GNU Affero General Public License v3.0.

Moral Rights asserted by PowerTea-2 under EU copyright law.

Any derivative must:

    Clearly mark itself as a fork

    Preserve the “Founding Architect” credit in all UI elements

    Label any deviation from v0.5 spec as “Unverified Implementation”

See NOTICE and LICENSE for full terms.

༺ ════════════════════════ ☾ ★ ☽ ════════════════════════ ༻
📖 Documentation & Security

    Full Protocol Spec — MPCP_v0.5_FINAL_PowerTea-2.pdf

    Legal Notice — NOTICE

    🔒 Security & Research Note

    MPCP is provided strictly for privacy research and educational use.

    No warranty. Use at your own risk.

<div align="center">

༺ ═════════════════════ ⋆⋅☆⋅⋆ ═════════════════════ ༻
Created under starlight by PowerTea-2 🌌

</div>
