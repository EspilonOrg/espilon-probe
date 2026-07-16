"""A minimal, flag-free UDS reference model - the FRAMED twin of console.py.

The SAME model bound two ways (docs/design/can-framed.md sections 3, 4): served in-process behind
the virtual CanFrameMedium, and run as a SEPARATE responder process bound to vcan0 on the real side.
Because both terminations run identical code, any frame difference the harness observes is a
TRANSPORT difference - which is exactly what the conformance diff is there to catch.

Deliberately minimal: the trio 10/27/22 - DiagnosticSessionControl, a seed->key SecurityAccess gate,
and a gated privileged ReadDataByIdentifier - plus the NRC branches the harness diffs. It exercises
session state, a security gate, a gated privileged read, and the negative-response paths: the whole
"stateful secret behind a request" pattern the pilot proves over two terminations, and nothing more.

NO flag, NO challenge content. Single-frame only: the privileged DID value is capped at 4 bytes so
every response PDU fits one ISO-TP single frame. The full kit UdsEcu (emit/payload flag staging,
assert_clean, multi-frame ISO-TP with FlowControl/STmin, the can-uds-unlock rewrite) is a SEPARATE
follow-up.

Model contract (delivery-agnostic, mirrors Console): `request(pdu) -> pdu | None` holds
session/security state across calls; the adapter (can_isotp) wraps the SF and the CAN ids.
"""

from __future__ import annotations

# services
SID_SESSION = 0x10          # DiagnosticSessionControl
SID_SECURITY = 0x27         # SecurityAccess
SID_READ_DID = 0x22         # ReadDataByIdentifier
NR = 0x7F                   # negative-response service id

# NRCs (the branches docs/design/can-framed.md section 3.1 requires, plus requestOutOfRange for a
# genuinely unknown DID - see the note on _read_did)
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNC_NOT_SUPPORTED = 0x12
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_OUT_OF_RANGE = 0x31
NRC_SECURITY_DENIED = 0x33
NRC_INVALID_KEY = 0x35

# fixed, course-visible constants (NOT secret - the pilot stages no flag). The seed is FIXED, so it
# is IN diff scope (must match both terminations); a random seed would be normalized out, this is
# not one (docs/design/can-framed.md section 4.4).
SEED = b"\x11\x22\x33\x44"
KEY_MASK = 0xA5A5A5A5
EXTENDED_SESSION = 0x03
PRIV_DID = 0xF190
PRIV_VALUE = b"\xDE\xAD\xBE\xEF"    # non-secret sentinel in the privileged slot (kit stages the flag)


def key_for(seed: bytes) -> bytes:
    """The expected sendKey answer for a seed: seed XOR the fixed mask, big-endian, 4 bytes."""
    return (int.from_bytes(seed, "big") ^ KEY_MASK).to_bytes(4, "big")


class UdsEcu:
    def __init__(self):
        self.session_extended = False
        self.seed_issued = False
        self.unlocked = False

    def request(self, pdu: bytes) -> bytes | None:
        """Feed one UDS request PDU; return the UDS response PDU, or None for no response. Holds
        session/security state across calls. NO CAN, NO ISO-TP here - the adapter wraps SF + ids."""
        pdu = bytes(pdu)
        if not pdu:
            return None                     # no service byte: a real ECU stays silent
        sid = pdu[0]
        if sid == SID_SESSION:
            return self._session(pdu)
        if sid == SID_SECURITY:
            return self._security(pdu)
        if sid == SID_READ_DID:
            return self._read_did(pdu)
        return self._nrc(sid, NRC_SERVICE_NOT_SUPPORTED)

    def _session(self, pdu: bytes) -> bytes:
        if len(pdu) < 2:
            return self._nrc(SID_SESSION, NRC_CONDITIONS_NOT_CORRECT)
        sub = pdu[1]
        if sub != EXTENDED_SESSION:
            return self._nrc(SID_SESSION, NRC_SUBFUNC_NOT_SUPPORTED)
        self.session_extended = True
        # 50 03 <P2=0x0032> <P2*=0x01F4>: the positive DiagnosticSessionControl with P2 timings.
        return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])

    def _security(self, pdu: bytes) -> bytes:
        if len(pdu) < 2:
            return self._nrc(SID_SECURITY, NRC_CONDITIONS_NOT_CORRECT)
        sub = pdu[1]
        if sub == 0x01:                     # requestSeed
            if not self.session_extended:
                return self._nrc(SID_SECURITY, NRC_SECURITY_DENIED)   # 27 01 before the session
            self.seed_issued = True
            return bytes([0x67, 0x01]) + SEED
        if sub == 0x02:                     # sendKey
            if not self.seed_issued:
                return self._nrc(SID_SECURITY, NRC_CONDITIONS_NOT_CORRECT)   # key with no pending seed
            if pdu[2:] != key_for(SEED):
                # Wrong key: state does NOT advance (stays locked), and the seed stays valid so a
                # subsequent correct key still unlocks - the exact "retry with the right key" path
                # the smoke tape exercises.
                return self._nrc(SID_SECURITY, NRC_INVALID_KEY)
            self.unlocked = True
            return bytes([0x67, 0x02])
        return self._nrc(SID_SECURITY, NRC_SUBFUNC_NOT_SUPPORTED)

    def _read_did(self, pdu: bytes) -> bytes:
        if len(pdu) < 3:
            return self._nrc(SID_READ_DID, NRC_CONDITIONS_NOT_CORRECT)
        did = (pdu[1] << 8) | pdu[2]
        if not self.unlocked:
            return self._nrc(SID_READ_DID, NRC_SECURITY_DENIED)      # privileged read before unlock
        if did != PRIV_DID:
            # An unlocked read of an unknown DID: requestOutOfRange is the ONE authoritative UDS
            # answer. Returning a within-set-but-wrong NRC would be a guess, so we answer correctly.
            return self._nrc(SID_READ_DID, NRC_REQUEST_OUT_OF_RANGE)
        return bytes([0x62, pdu[1], pdu[2]]) + PRIV_VALUE

    def _nrc(self, sid: int, nrc: int) -> bytes:
        return bytes([NR, sid, nrc])

    def idle_surfaces(self) -> list[bytes]:
        """Non-secret surfaces for a future assert_clean audit (banner-equivalent). This pilot model
        stages no flag, so every surface here is non-secret by construction; the real audit lands
        with the kit UdsEcu."""
        return [bytes([0x50, EXTENDED_SESSION, 0x00, 0x32, 0x01, 0xF4])]
