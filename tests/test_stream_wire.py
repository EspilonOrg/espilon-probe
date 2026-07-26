"""The RAW-STREAM wire delta: STREAM_ATTACH / STREAM_READY control messages (docs/01 section 3).

These are the ENTIRE wire change for the raw regime. The FRAMED codec (encode/decode/Frame) is
untouched; this only asserts the two new control messages and their constructors round-trip and
carry the half-duplex mode hint.
"""

import io

from espilon_probe.core import wire


def test_stream_attach_constructor_and_default_mode():
    m = wire.stream_attach()
    assert m == {"t": wire.STREAM_ATTACH, "mode": "duplex"}
    assert wire.stream_attach("read")["mode"] == "read"
    assert wire.stream_attach("write")["mode"] == "write"


def test_stream_ready_constructor():
    assert wire.stream_ready() == {"t": wire.STREAM_READY}


def test_stream_messages_roundtrip_through_the_framed_codec():
    # The upgrade is negotiated framed (before the raw seam), so both control messages must encode
    # and decode through the ordinary length-prefixed codec.
    for msg in (wire.stream_attach("read"), wire.stream_ready()):
        stream = io.BytesIO(wire.encode(msg))
        assert wire.decode(stream) == msg


def test_types_are_distinct_stable_strings():
    assert wire.STREAM_ATTACH == "stream_attach"
    assert wire.STREAM_READY == "stream_ready"
    assert wire.STREAM_ATTACH != wire.STREAM_READY
