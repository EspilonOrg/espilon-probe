"""sub-GHz protocol: ISM-band packet radio + the `subghz` verb group.

Shape: PACKET (radio) (see docs/protocol-subghz.md). Unlike JTAG/SPI this IS a radio, so all
four core verbs apply (`scan`/`sniff`/`inject`/`replay`), BOUNDED per convention rule 4 (the
client enforces count/seconds/timeout on every receive; the sniff loop already lives in the
virtual backend). The radio-specific args (`--freq`/`--mod`/`--rate`) extend the existing core
verbs rather than adding new ones, so the surface stays uniform with the other PACKET
protocols.

Captures carry DEMODULATED packets (not raw IQ), under DLT_USER_PROBE_SUBGHZ = 147 with a
documented 8-byte pseudo-header so the capture self-describes the radio params and is
replayable without external state. `replay` validates the pcap DLT == 147 (convention C4, in
the shared replay path) and reads freq/mod/rate from each frame's pseudo-header by default.

The `subghz` protocol verbs are HINTS only: `demod` reports a best-effort modulation/bitrate
guess for a capture the operator already has (it does NOT decode payload meaning - decoding
stays in the operator's stock tools), and `bands` lists the ISM bands. Both
travel over the existing `op()` carrier, so the identical commands later run against a real
`sdr`/`cc1101` backend; the pseudo-header and verb surface are unchanged.
"""

from __future__ import annotations

import struct

from ..core.backend import Backend
from ..core.errors import ProbeError
from ..core.frame import DLT_USER_PROBE_SUBGHZ

PROTOCOL = "subghz"
VERBS = ["scan", "sniff", "inject", "replay", "subghz"]
PCAP_DLT = DLT_USER_PROBE_SUBGHZ        # 147, the radio capture link type

# 8-byte pseudo-header (docs/protocol-subghz.md section 4), all multi-byte LE:
#   0  u32 freq_hz | 4 u8 modulation | 5 u16 bitrate | 7 u8 payload_len | 8.. payload
_PHDR = struct.Struct("<IBHB")
PSEUDO_HEADER_LEN = _PHDR.size          # 8

# modulation code map (1=ook 2=ask 3=2fsk 4=gfsk). Authoritative both ways.
_MOD_TO_CODE = {"ook": 1, "ask": 2, "2fsk": 3, "gfsk": 4}
_CODE_TO_MOD = {v: k for k, v in _MOD_TO_CODE.items()}
MODULATIONS = list(_MOD_TO_CODE)

DEFAULT_RATE = 2000                     # symbols/s, matches meta.default_rate


def parse_freq(text: str | int) -> int:
    """Parse a frequency to integer Hz. Accepts `433.92M` / `868.3M` / `915M` / a raw Hz int.

    Conservative: an unparseable value is a clean `ProbeError`, never a silent default. This
    is operator-supplied input that selects the transmit/capture frequency, so a wrong guess
    would put energy on the wrong channel.
    """
    if isinstance(text, int):
        if text <= 0:
            raise ProbeError(f"subghz: frequency must be positive, got {text}")
        return text
    s = str(text).strip().lower()
    if not s:
        raise ProbeError("subghz: empty frequency")
    mult = 1
    if s.endswith("m"):
        mult, s = 1_000_000, s[:-1]
    elif s.endswith("k"):
        mult, s = 1_000, s[:-1]
    elif s.endswith("g"):
        mult, s = 1_000_000_000, s[:-1]
    elif s.endswith("hz"):
        s = s[:-2]
    try:
        value = float(s)
    except ValueError:
        raise ProbeError(f"subghz: cannot parse frequency {text!r}")
    hz = int(round(value * mult))
    if hz <= 0:
        raise ProbeError(f"subghz: frequency must be positive, got {text!r}")
    return hz


def mod_code(mod: str) -> int:
    """Map a modulation name to its pseudo-header code, refusing an unknown one cleanly."""
    code = _MOD_TO_CODE.get(str(mod).strip().lower())
    if code is None:
        raise ProbeError(
            f"subghz: unknown modulation {mod!r} (supported: {', '.join(MODULATIONS)})")
    return code


def mod_name(code: int) -> str:
    """Map a pseudo-header modulation code back to its name, refusing an unknown one."""
    name = _CODE_TO_MOD.get(int(code))
    if name is None:
        raise ProbeError(f"subghz: unknown modulation code {code}")
    return name


def encode_frame(payload: bytes, freq: str | int, mod: str, rate: int = DEFAULT_RATE) -> bytes:
    """Build a sub-GHz on-wire frame: the 8-byte pseudo-header + the demod payload.

    The pseudo-header is the authoritative copy of the radio params written into the pcap, so
    a capture is replayable without external state. Field widths are validated so a too-large
    payload/bitrate is a clean error, not a silent wrap.
    """
    payload = bytes(payload)
    if len(payload) > 0xFF:
        raise ProbeError(
            f"subghz: payload too long for the pseudo-header ({len(payload)} > 255 bytes)")
    if not 0 <= int(rate) <= 0xFFFF:
        raise ProbeError(f"subghz: bitrate out of range: {rate} (must fit 16 bits)")
    hz = parse_freq(freq)
    if hz > 0xFFFFFFFF:
        raise ProbeError(f"subghz: frequency {hz} Hz does not fit the u32 pseudo-header")
    header = _PHDR.pack(hz, mod_code(mod), int(rate), len(payload))
    return header + payload


def decode_frame(raw: bytes) -> dict:
    """Parse a sub-GHz on-wire frame back to `{freq, mod, rate, payload}`.

    Conservative: a buffer shorter than the pseudo-header, or whose declared payload length
    does not match the bytes present, is a hard `ProbeError`. We never guess the radio params
    of a malformed capture (that would let a wrong frequency/modulation onto a replay).
    """
    raw = bytes(raw)
    if len(raw) < PSEUDO_HEADER_LEN:
        raise ProbeError(
            f"subghz: frame shorter than the {PSEUDO_HEADER_LEN}-byte pseudo-header "
            f"({len(raw)} bytes)")
    freq, code, rate, plen = _PHDR.unpack(raw[:PSEUDO_HEADER_LEN])
    payload = raw[PSEUDO_HEADER_LEN:]
    if len(payload) != plen:
        raise ProbeError(
            f"subghz: pseudo-header declares {plen} payload bytes but {len(payload)} are "
            f"present; refusing a malformed frame")
    return {"freq": freq, "mod": mod_name(code), "rate": rate, "payload": payload}


def _result(backend: Backend, verb: str, **kwargs) -> dict:
    """Call `op()` and guarantee a dict result (see jtag._result for the rationale).

    A null or non-dict result is a clean `ProbeError`, never an AttributeError from `.get()`.
    """
    res = backend.op(verb, **kwargs)
    if res is None:
        raise ProbeError(f"backend returned a null result for {verb}")
    if not isinstance(res, dict):
        raise ProbeError(f"backend returned a non-object result for {verb}: {res!r}")
    return res


# named protocol verbs (HINTS only; used by the CLI dispatch and by tests/scripts)
def demod(backend: Backend, capture: str | None = None) -> dict:
    """A modulation/bitrate/encoding HINT for a capture the operator already has.

    This is a guess to help the operator pick params; it does NOT decode the payload meaning
    (the conventions forbid building a solver into the client).
    """
    if capture is None:
        return _result(backend, "subghz.demod")
    return _result(backend, "subghz.demod", capture=capture)


def band_list(backend: Backend) -> list[dict]:
    """The advertised ISM bands, defensively normalized: a non-list `bands` is a clean
    `ProbeError` and non-dict rows are skipped, so the CLI display never tracebacks."""
    raw = _result(backend, "subghz.bands").get("bands", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ProbeError(f"backend returned non-list bands {raw!r}")
    return [band for band in raw if isinstance(band, dict)]


def bands(backend: Backend) -> dict:
    return _result(backend, "subghz.bands")
