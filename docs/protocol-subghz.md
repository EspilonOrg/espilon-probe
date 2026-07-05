# Protocol: sub-GHz (virtual)

Read `protocol-conventions.md` first. This doc specifies `protocols/subghz.py` and what a
virtual backend must simulate.

## 1. What it models

An operator with an SDR (HackRF / RTL-SDR via SoapySDR) or a CC1101-class transceiver
working the ISM bands (433 / 868 / 915 MHz) against simple OOK/ASK and 2-FSK devices:
remotes, sensors, alarm fobs, garage/gate openers.

- scan a band for active frequencies / energy (a quick spectrum/energy sweep),
- sniff/capture demodulated packets to a pcap,
- transmit (inject) a crafted packet on a frequency+modulation,
- replay a previously captured packet (the classic fixed-code remote replay),
- get a demod HINT (modulation/bitrate/encoding guess) to help the operator pick params.

Unlike JTAG/SPI this IS a radio: packet/sample oriented, so the four core verbs apply. They
are BOUNDED per `protocol-conventions.md` rule 4.

Tradecraft mapping:

| Real tool | probe verb |
|---|---|
| `rtl_power` / quick energy sweep | `probe scan` |
| `rpitx`/`urh` capture, `rtl_433` | `probe sniff -w cap.pcap --freq 433.92M --mod ook` |
| `urh`/`rfcat` transmit | `probe inject --hex ... --freq ... --mod ...` |
| replay a fixed-code remote | `probe replay -r cap.pcap` |
| `urh` auto-detect / `rtl_433 -A` | `probe subghz demod -r cap.pcap` |

## 2. Shape and verb set

Shape: PACKET (radio). All four core verbs apply, BOUNDED.

Core verbs:

| Core verb | sub-GHz | Notes |
|---|---|---|
| `scan` | OFFERED | band energy sweep -> active frequencies |
| `sniff` | OFFERED, BOUNDED | demod packets to pcap; client enforces count/seconds/timeout |
| `inject` | OFFERED | transmit one packet on `--freq`/`--mod` |
| `replay` | OFFERED | re-transmit captured packets; DLT-vs-session validated |

No core verb is gated out. The radio-specific args (`--freq`, `--mod`, `--rate`) extend the
existing core verbs rather than adding new ones, so the surface stays uniform with the other
PACKET protocols.

Protocol verbs (group `subghz`):

| CLI | op verb | args | returns |
|---|---|---|---|
| `probe subghz demod` | `subghz.demod` | `-r cap.pcap` (or last capture) | `{modulation, bitrate, encoding, guess_conf}` |
| `probe subghz bands` | `subghz.bands` | - | `{bands:[{name, lo, hi, default}]}` |

`demod` is a HINT only (the conventions forbid building a solver into the client). It reads a
capture the operator already has and reports a best-effort guess (OOK vs 2-FSK, bitrate,
Manchester/PWM) so the operator can choose params; it does NOT decode the payload meaning.
Decoding stays in the operator's stock tools (`rtl_433`, `urh`).

Radio args added to the core verbs:

```
probe sniff  -w cap.pcap --freq 433.92M --mod ook [--rate 2000] [-c N] [-t S]
probe inject --hex AABBCC  --freq 433.92M --mod ook [--rate 2000]
probe scan   [--band 433|868|915]
probe replay -r cap.pcap   [--freq F] [--mod M]      # defaults read from the pcap header
```

`--freq` accepts `433.92M` / `868.3M` / a raw Hz int. `--mod` in `{ook, ask, 2fsk, gfsk}`.
`--rate` is baud/symbol-rate; default per band in `meta`.

## 3. `capabilities()` shape

```python
Capabilities(
    protocol="subghz",
    transport="virtual",                 # later "sdr" (SoapySDR) or "cc1101"
    channels=[433920000, 868300000, 915000000],   # representative center freqs in Hz
    verbs=["scan", "sniff", "inject", "replay", "subghz"],
    meta={
        "shape": "packet",               # contract item C2
        "bands": [
            {"name": "433", "lo": 433050000, "hi": 434790000, "default": 433920000},
            {"name": "868", "lo": 863000000, "hi": 870000000, "default": 868300000},
            {"name": "915", "lo": 902000000, "hi": 928000000, "default": 915000000},
        ],
        "modulations": ["ook", "ask", "2fsk", "gfsk"],
        "default_rate": 2000,            # symbols/s
        "sniff_default_seconds": 30.0,   # client ceiling when no bound given (rule 4)
    },
)
```

`channels` reuses the existing int-channel field with center frequencies in Hz, so
`--channel` and `--freq` both resolve to a frequency; `info` prints them.

## 4. DLT and capture representation

sub-GHz captures demodulated PACKETS (not raw IQ - IQ is out of scope; we capture symbols,
like `rtl_433` emits decoded packets). There is no perfectly-matching standard DLT for a
generic ISM packet carrying our band/mod metadata, so we allocate
`DLT_USER_PROBE_SUBGHZ = 147` (USER0) with a documented 8-byte pseudo-header so the capture
self-describes the radio params (essential for a correct `replay`).

Per-frame on-wire layout (`Frame.raw` = pseudo-header + payload), all multi-byte LE:

```
offset  size  field
0       4     freq_hz       (center frequency, u32)
4       1     modulation    (1=ook 2=ask 3=2fsk 4=gfsk)
5       2     bitrate       (symbols/s, u16)
7       1     payload_len   (bytes of demod payload following)
8       ...   payload       (demodulated packet bytes)
```

The `Frame.meta` carries the same params (`{freq, mod, rate}`) for tools that read the JSON
side; the pseudo-header is the authoritative copy written into the pcap so the capture is
replayable without external state. We ship the layout (this table), not a dissector; a
trivial Lua/scapy reader decodes it, and stock tools see well-formed `USER0` records.

`replay` reads `freq`/`mod`/`rate` from each frame's pseudo-header by default (so a captured
remote replays on its original frequency) and validates the pcap DLT == 147, refusing a
non-sub-GHz capture with `ProbeError` (rule 5). `--freq`/`--mod` on the CLI override the
header.

Bound enforcement (rule 4): `sniff` REQUIRES `count` or `seconds`; if neither is given the
client uses `meta.sniff_default_seconds` (30s). The client stops at
`frames >= count OR elapsed >= seconds OR elapsed >= timeout` and then sends stop, regardless
of further server frames. This is the explicit fix for the unbounded-sniff finding.

## 5. What a virtual target must simulate

A virtual target exposes an RF environment:

- a set of emitters, each on a `freq`/`mod`/`bitrate`, periodically emitting a packet
  payload (the target server pushes these as `FRAME` during a `sniff`). `scan` reports which
  frequencies show energy.
- a receiver model for `inject`/`replay`: the device accepts a transmitted packet only if
  `freq`/`mod`/`rate` match within tolerance AND the payload matches what the device expects
  (e.g. the exact fixed-code of a remote). A matching transmit mutates device state
  (door "opens").
- a gated response behind a correct transmit. Two canonical shapes:
  1. fixed-code replay: sniff the remote's packet, replay it, the device unlocks and the
     target emits a result (as a subsequent FRAME or an `op` result).
  2. rolling/encoded: the operator must `subghz demod` to find the encoding, craft the
     right payload, and `inject` it. The result is delivered over the wire on success.

Backend hooks a virtual target implements:

```
on_scan()                    -> [{freq, energy, mod?}]      # active frequencies
on_sniff(freq, mod, ...)     -> yields FRAME(raw=pseudohdr+payload) until client bound
on_inject(frame, freq, mod)  -> {ok}    # match -> mutate state, maybe emit a result frame
on_replay(frames)            -> {count}
on_op("subghz.demod", cap)   -> {modulation, bitrate, encoding, guess_conf}
on_op("subghz.bands")        -> {bands:[...]}
```

Same-commands-transfer note: the identical `probe sniff/inject/replay --freq --mod` commands
later run against the `sdr` real backend (SoapySDR + the project's OOK/2-FSK demod/mod, the
one genuinely low-level backend per ARCHITECTURE.md) or a `cc1101` backend. The pseudo-header
and verb surface are unchanged; the real backend fills the same fields from actual RF. A
"sniff -> replay a 433 MHz fob" workflow transfers directly to a real HackRF.

## 6. Contract-evolution items touched

- C1 (`ProbeError`) - used by `replay` DLT-mismatch refusal; no core verb is gated out here.
- C2 (`Capabilities.shape`) - sub-GHz sets `shape="packet"`.
- C4 (`replay` DLT-vs-session validation) - sub-GHz exercises it (must reject non-147 pcaps).
- The sniff client-bound (rule 4) is the load-bearing fix this protocol must implement; it is
  a CLI/backend behavior, not a contract change.
- No new Backend method, no new wire message type: `sniff`/`inject`/`replay`/`op` already
  cover everything; radio params travel in existing `meta`/args and the pseudo-header.
