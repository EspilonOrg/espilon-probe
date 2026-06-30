"""SPI protocol: verb set, capability gating, JEDEC-ID enumerate, dump artifact, xfer.

SPI master is a TRANSACTION protocol: it advertises only ["scan", "spi"], so
sniff/inject/replay are gated OUT (convention C1) and fail clean. `scan` is repurposed as
JEDEC-ID enumeration. `spi dump` writes a RAW BINARY flash image (the default artifact),
optionally with a transaction pcap under DLT_USER_PROBE_SPI (148).
"""

import os

import pytest

from espilon_probe import cli
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError
from espilon_probe.core.frame import DLT_USER_PROBE_SPI, read_pcap

from _mock_bridge import serve_mock

SPI_CAPS = {"protocol": "spi", "channels": [], "verbs": ["scan", "spi"],
            "shape": "transaction", "pcap_dlt": DLT_USER_PROBE_SPI,
            "meta": {"chip_selects": 1, "flash": {"size": 0x800000}}}


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


def _spi_respond(flash):
    """A scripted NOR: JEDEC id + a backing byte array `flash` (bytes)."""
    def respond(msg):
        if msg.get("t") != wire.OP:
            return wire.error("unhandled")
        verb = msg.get("verb")
        a = msg.get("args", {})
        if verb == "spi.id":
            return {"t": wire.OP_RESULT, "result": {
                "jedec_id": 0xC22016, "manufacturer": "macronix",
                "capacity": "4MiB", "name": "MX25L3206E"}}
        if verb == "spi.read":
            addr, n = a["addr"], a["len"]
            chunk = flash[addr:addr + n]
            chunk = chunk + b"\xff" * (n - len(chunk))   # pad like a real read off-end
            return {"t": wire.OP_RESULT, "result": {"addr": addr, "data": chunk.hex()}}
        if verb == "spi.xfer":
            mosi = bytes.fromhex(a["mosi"])
            # echo back JEDEC for a 9F command, else zeros of the same length (full-duplex)
            if mosi[:1] == b"\x9f":
                miso = b"\x9f\xc2\x20\x16"[:len(mosi)].ljust(len(mosi), b"\x00")
            else:
                miso = b"\x00" * len(mosi)
            return {"t": wire.OP_RESULT, "result": {"miso": miso.hex()}}
        return wire.error(f"unhandled verb {verb}")

    return respond


def test_capabilities_verb_set():
    assert "scan" in SPI_CAPS["verbs"] and "spi" in SPI_CAPS["verbs"]
    for gated in ("sniff", "inject", "replay"):
        assert gated not in SPI_CAPS["verbs"]


@pytest.mark.parametrize("gated", ["sniff", "inject", "replay"])
def test_gated_core_verbs_fail_clean(gated, capsys, tmp_path):
    srv, port = serve_mock(SPI_CAPS, _spi_respond(b""))
    try:
        if gated == "sniff":
            argv = ["sniff", "-w", str(tmp_path / "x.pcap"), "-c", "1"]
        elif gated == "inject":
            argv = ["inject", "--hex", "00"]
        else:
            argv = ["replay", "-r", str(tmp_path / "x.pcap")]
        with pytest.raises(SystemExit) as ei:
            _run(argv, port, capsys)
        assert f"'{gated}' is not supported on protocol 'spi'" in str(ei.value)
        assert "supported: scan, spi" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_scan_enumerates_jedec(capsys):
    srv, port = serve_mock(SPI_CAPS, _spi_respond(b""))
    try:
        out = _run(["scan"], port, capsys)
        assert "0xc22016" in out
        assert "MX25L3206E" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_spi_id(capsys):
    srv, port = serve_mock(SPI_CAPS, _spi_respond(b""))
    try:
        out = _run(["spi", "id"], port, capsys)
        assert "jedec=0xc22016" in out
        assert "macronix" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_spi_xfer_full_duplex(capsys):
    srv, port = serve_mock(SPI_CAPS, _spi_respond(b""))
    try:
        out = _run(["spi", "xfer", "--hex", "9f000000"], port, capsys)
        assert out.strip() == "9fc22016"
    finally:
        srv.shutdown()
        srv.server_close()


def test_spi_dump_writes_raw_binary(tmp_path, capsys):
    flash = bytes(range(64))
    srv, port = serve_mock(SPI_CAPS, _spi_respond(flash))
    try:
        out_bin = tmp_path / "flash.bin"
        out = _run(["spi", "dump", "--addr", "0", "--len", "64", "-w", str(out_bin)],
                   port, capsys)
        assert "dumped 64 byte(s)" in out
        assert out_bin.read_bytes() == flash
    finally:
        srv.shutdown()
        srv.server_close()


def test_spi_dump_optional_pcap_uses_dlt_148(tmp_path, capsys):
    flash = b"\xaa\xbb\xcc\xdd"
    srv, port = serve_mock(SPI_CAPS, _spi_respond(flash))
    try:
        out_bin = tmp_path / "flash.bin"
        out_pcap = tmp_path / "sess.pcap"
        _run(["spi", "dump", "--addr", "0", "--len", "4",
              "-w", str(out_bin), "--pcap", str(out_pcap)], port, capsys)
        dlt, recs = read_pcap(str(out_pcap))
        assert dlt == DLT_USER_PROBE_SPI == 148
        assert len(recs) == 1
        assert recs[0][0] == 2          # op byte == read
        assert recs[0].endswith(flash)
    finally:
        srv.shutdown()
        srv.server_close()


def test_spi_dump_length_ceiling_refused():
    from espilon_probe.protocols import spi

    class _B:
        def op(self, *a, **k):
            raise AssertionError("backend must not be called for an over-ceiling dump")

    with pytest.raises(ProbeError) as ei:
        spi.dump(_B(), spi.DUMP_MAX_BYTES + 1, "/tmp/should-not-write.bin")
    assert "exceeds the client ceiling" in str(ei.value)
