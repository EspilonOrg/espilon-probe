"""UdsEcu model unit tests (no socket) + the can_isotp single-frame round-trip.

The FRAMED twin of the Console.feed model tests: feed request PDUs directly to UdsEcu.request and
assert byte-exact response PDUs, every NRC branch, and that a wrong sendKey does NOT advance state
and a pre-unlock privileged read is denied (docs/protocols/can-framed.md sections 3, 6).
"""

import pytest

from conformance import can_isotp
from conformance.uds_ecu import PRIV_VALUE, SEED, UdsEcu, key_for


# --- can_isotp single-frame round-trip -----------------------------------------------------------

def test_sf_wrap_unwrap_roundtrip():
    for pdu in (b"", b"\x10\x03", b"\x62\xf1\x90\xde\xad\xbe\xef"):
        data = can_isotp.sf_wrap(pdu)
        assert len(data) == 8                          # always padded to the fixed 8-byte payload
        assert data[0] == len(pdu)                     # PCI: SF type nibble 0, length low nibble
        assert can_isotp.sf_unwrap(data) == pdu


def test_sf_wrap_rejects_oversize():
    with pytest.raises(can_isotp.IsoTpError):
        can_isotp.sf_wrap(b"\x00" * 8)                 # 8 > SF_MAX (7)


def test_sf_unwrap_rejects_multiframe_and_truncated():
    with pytest.raises(can_isotp.IsoTpError):
        can_isotp.sf_unwrap(b"\x10\x14\x62")           # PCI type 1 = first frame, not SF
    with pytest.raises(can_isotp.IsoTpError):
        can_isotp.sf_unwrap(b"\x05\x62\xf1")           # SF claims 5 bytes, only 2 present


def test_request_response_frame_roundtrip():
    req = can_isotp.encode_request(b"\x10\x03")
    cid, pdu = can_isotp.decode(req)
    assert cid == can_isotp.REQ_ID and pdu == b"\x10\x03"
    resp = can_isotp.encode_response(b"\x50\x03")
    cid, pdu = can_isotp.decode(resp)
    assert cid == can_isotp.RESP_ID and pdu == b"\x50\x03"


# --- UdsEcu services -----------------------------------------------------------------------------

def test_session_control_opens_extended():
    ecu = UdsEcu()
    assert ecu.request(b"\x10\x03") == b"\x50\x03\x00\x32\x01\xf4"
    assert ecu.session_extended is True


def test_seed_then_correct_key_unlocks():
    ecu = UdsEcu()
    ecu.request(b"\x10\x03")
    assert ecu.request(b"\x27\x01") == b"\x67\x01" + SEED
    key = key_for(SEED)
    assert ecu.request(b"\x27\x02" + key) == b"\x67\x02"
    assert ecu.unlocked is True


def test_privileged_read_served_only_after_unlock():
    ecu = UdsEcu()
    # pre-unlock: denied with NRC 0x33, value NEVER returned
    assert ecu.request(b"\x22\xf1\x90") == b"\x7f\x22\x33"
    ecu.request(b"\x10\x03")
    ecu.request(b"\x27\x01")
    ecu.request(b"\x27\x02" + key_for(SEED))
    assert ecu.request(b"\x22\xf1\x90") == b"\x62\xf1\x90" + PRIV_VALUE


# --- NRC branches --------------------------------------------------------------------------------

def test_request_seed_before_session_is_denied():
    assert UdsEcu().request(b"\x27\x01") == b"\x7f\x27\x33"      # securityAccessDenied


def test_send_key_before_seed_is_conditions_not_correct():
    ecu = UdsEcu()
    ecu.request(b"\x10\x03")
    assert ecu.request(b"\x27\x02\x00\x00\x00\x00") == b"\x7f\x27\x22"   # conditionsNotCorrect


def test_wrong_key_is_invalid_key_and_does_not_advance_state():
    ecu = UdsEcu()
    ecu.request(b"\x10\x03")
    ecu.request(b"\x27\x01")
    assert ecu.request(b"\x27\x02\x00\x00\x00\x00") == b"\x7f\x27\x35"   # invalidKey
    assert ecu.unlocked is False
    # the seed stays valid, so the correct key still unlocks after a wrong attempt
    assert ecu.request(b"\x27\x02" + key_for(SEED)) == b"\x67\x02"
    assert ecu.unlocked is True


def test_unknown_service_is_service_not_supported():
    assert UdsEcu().request(b"\x3e\x00") == b"\x7f\x3e\x11"      # serviceNotSupported


def test_unknown_subfunction_is_subfunc_not_supported():
    assert UdsEcu().request(b"\x10\x99") == b"\x7f\x10\x12"      # subFunctionNotSupported (session)
    assert UdsEcu().request(b"\x27\x99") == b"\x7f\x27\x12"      # subFunctionNotSupported (security)


def test_unknown_did_when_unlocked_is_request_out_of_range():
    ecu = UdsEcu()
    ecu.request(b"\x10\x03")
    ecu.request(b"\x27\x01")
    ecu.request(b"\x27\x02" + key_for(SEED))
    assert ecu.request(b"\x22\xf1\x91") == b"\x7f\x22\x31"       # requestOutOfRange


def test_empty_pdu_is_silent():
    assert UdsEcu().request(b"") is None


def test_privileged_value_fits_single_frame():
    # The pilot's SF-only claim: 62 F1 90 <value> must fit one single frame (<= 7 bytes total).
    ecu = UdsEcu()
    ecu.request(b"\x10\x03")
    ecu.request(b"\x27\x01")
    ecu.request(b"\x27\x02" + key_for(SEED))
    resp = ecu.request(b"\x22\xf1\x90")
    assert len(resp) <= 7
    can_isotp.sf_wrap(resp)                             # must not raise (fits an SF)
