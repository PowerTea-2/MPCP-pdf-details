# ClockWork

```text
        .-===========-.
        |  CLOCKWORK  |
        |   00:00:00  |
        '-===========-'

        ⚙      ⚙      ⚙
     ⚙     ⚙      ⚙     ⚙
        ⚙      ⚙      ⚙
```

A file transfer system that does not rely on connection — only agreement.

---

## What it is

ClockWork is a file transfer application built on top of the **MPCP (Multi-Port Catch Protocol)**.

It does not stream data over a stable connection.
It schedules it.

Both sides independently follow the same:

* timing windows
* port sequence
* cryptographic schedule

The file emerges from alignment, not continuity.

---

## Mechanical Model

```text
        [ SENDER ]
             ⚙
      (chunk → encrypt)
             ⚙
      (time-slot emit)
             ⚙
        ports rotate
   4102 → 5931 → 7773 → ...
             ⚙
             ▼

        [ RECEIVER ]
             ⚙
      (multi-port intake)
             ⚙
      (time alignment)
             ⚙
      (reassembly engine)
             ⚙
           FILE
```

Each gear is independent.
Nothing “holds” the connection together.

---

## Core Behaviors (from code)

### Time is the transport

```text
send(packet, t = exact)
receive(window = computed)
```

* nanosecond clocks (`clock_gettime`)
* calibrated RTT using trimmed mean + MAD + EWMA
* adaptive catch window per session

The network is noisy.
ClockWork models the noise, then moves through it.

---

### Multi-port sequencing

```text
chunk[i] → port = f(session_key, i)
```

* ports derived from HKDF keystream
* wide port range (default ~55k span)
* no fixed channel

Packets do not form a stream.
They scatter and are re-collected.

---

### Encrypted chunk engine

```text
plaintext → pad → encrypt → emit
```

* XChaCha20-Poly1305 per chunk
* unique nonce per emission
* fixed-size padded chunks (traffic shaping)

All chunks look the same.
Real and fake are indistinguishable.

---

### Ghost traffic

```text
real:   [data]
ghost:  [indistinguishable noise]
```

* deterministic ghost map from session key
* injected into stream as valid ciphertext
* receiver discards via schedule knowledge

Noise is not decoration.
It is structural.

---

### No connection state

```text
(no TCP)
(no stream)
(no session socket)
```

* UDP / raw send
* no handshake persistence
* no teardown signal

Start → operate → disappear

---

### Tripwire system

```text
anomaly → zero keys → exit(0)
```

* z-score RTT anomaly detection
* loss-pattern analysis (chi-squared)
* silent abort + canary log

Failure is not reported.
It is erased.

---

### Pipeline architecture

```text
[read] → [compress] → [encrypt] → [send]
```

* lock-free ring buffers
* multi-threaded stages
* optional zero-copy + batched syscalls

Work flows forward continuously.
No stage waits longer than needed.

---

### Key system

```text
N candidate keys → blind selection → 1 survives
```

* parallel key candidates
* constant-time selection (receiver side)
* all unused keys wiped immediately

Only one path becomes real.

---

## Visualization: timing-driven transfer

```text
Time ─────────────────────────────────▶

Sender:    [pkt]     [pkt]      [pkt]
              │         │          │
              ▼         ▼          ▼
Ports:     4102      5931       7773
              │         │          │
              ▼         ▼          ▼
Receiver:  [buf]     [buf]      [buf]

Reconstruction:
   t0 → t1 → t2 → reorder → file
```

No continuous stream.
Only correct arrival within time windows.

---

## Build

```bash
gcc -std=c11 -D_GNU_SOURCE -O2 ClockWork.c -o clockwork -lsodium -lzstd -lm -lpthread
```

---

## Run

```bash
./clockwork
./clockwork --test
./clockwork --selftest
./clockwork --bench
./clockwork -v
```

---

## Design Summary

ClockWork behaves like a machine:

* timing is the drive shaft
* ports are rotating gears
* chunks are teeth
* the receiver is the assembly stage

Nothing is continuous.
Everything is coordinated.

---

## Spec

```text
ClockWork_v0.5_FINAL_PowerTea-2.pdf
```

---

## License

<define here>
