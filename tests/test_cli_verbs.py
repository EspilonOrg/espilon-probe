"""CLI verb-surface coverage: UART read/write and Zigbee packet capture over the bridge.

These exercise the dispatch paths the codec tests never reached: the `uart` group (a
byte-stream protocol) and a `sniff` against a Zigbee (802.15.4) protocol bridge.
"""

import os
import time

from espilon_probe import cli
from espilon_probe.core import wire

from _mock_bridge import serve_mock, serve_stream_mock


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


UART_CAPS = {"protocol": "uart", "channels": [], "verbs": ["scan", "uart"],
             "shape": "stream", "meta": {}}

ZIGBEE_CAPS = {"protocol": "zigbee", "channels": [11, 15, 25],
               "verbs": ["scan", "sniff", "inject", "replay"],
               "shape": "packet", "pcap_dlt": 195, "meta": {}}


def test_uart_write_and_read(capsys):
    # UART is RAW-STREAM: `uart write`/`uart read` go over the stream upgrade, not `op()`.
    # `write` prints `wrote N byte(s)`; `read` drains the line (the banner, then the echoed write).
    state = {"fifo": bytearray(b"boot> "), "writes": []}
    srv, port, state = serve_stream_mock(UART_CAPS, state)
    try:
        assert _run(["uart", "write", "help"], port, capsys) == "wrote 4 byte(s)\n"
        # The mock captures the write reactively on its handler thread; let it drain.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not state["writes"]:
            time.sleep(0.02)
        assert state["writes"] == [b"help"]
        # read drains the banner plus the echoed write bytes, in order.
        assert _run(["uart", "read", "-t", "1"], port, capsys) == "boot> help"
    finally:
        srv.shutdown()
        srv.server_close()


def test_zigbee_sniff_writes_pcap(tmp_path, capsys):
    # A Zigbee bridge streams two 802.15.4 frames then ends; the capture must land in a pcap
    # with the 802.15.4 DLT (195) the protocol declares.
    frames = [bytes.fromhex("6188"), bytes.fromhex("4188")]

    def respond(msg):
        # serve_mock sends one reply per message; answer SNIFF with a single frame and let the
        # client count-bound stop the capture (multi-frame streaming needs a streaming server,
        # covered separately in test_sniff_bound).
        if msg.get("t") == wire.SNIFF:
            return {"t": wire.FRAME, "ts": 0.0, "channel": 15, "direction": "rx",
                    "protocol": "zigbee", "raw": frames[0].hex(), "meta": {}}
        return None

    srv, port = serve_mock(ZIGBEE_CAPS, respond)
    try:
        out = _run(["sniff", "-w", str(tmp_path / "z.pcap"), "-c", "1"], port, capsys)
        assert "captured 1 frame(s)" in out
        from espilon_probe.core.frame import read_pcap
        dlt, got = read_pcap(str(tmp_path / "z.pcap"))
        assert dlt == 195
        assert got == [frames[0]]
    finally:
        srv.shutdown()
        srv.server_close()
