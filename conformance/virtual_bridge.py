"""The VIRTUAL bridge: serve the Console model over the TCP stream tunnel.

Key move for maximal fidelity: the virtual bridge reuses the EXACT SAME generic `BridgeServer`
(handshake, STREAM_ATTACH/READY, the half-duplex raw pump) that the real serial bridge uses. Only
the *medium* differs - here a `ConsoleMedium` that adapts the Console model to the same
drain()/write() surface the serial medium exposes. So virtual vs real is a one-line substitution
(ConsoleMedium vs SerialMedium) and even the pump code is shared. That is the corpus's "same
tunnel, two terminations" made literal (docs/design/00, docs/design/02, docs/design/04).

Persistence mirrors the pty: a write connection's Console output goes into this medium's FIFO and is
delivered to the NEXT read connection, exactly as the pty's RX buffer holds a response emitted after
the write connection closed until the read connection opens (docs/design/01 section 4).
"""

from __future__ import annotations

import threading

from espilon_probe.bridges.server import BridgeServer

from .console import Console


class ConsoleMedium:
    """Adapt a Console to the bridge medium surface (drain/write/caps/scan/apply_config/close)."""

    shape = "stream"

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._fifo = bytearray(self.console.banner())   # banner queued at device boot

    def apply_config(self, config: dict) -> None:
        # No bit clock in the model transport; baud is honoured by the kit garble model, not here
        # (the pilot's virtual bridge carries no garble - that is a model-side follow-up).
        pass

    def drain(self) -> bytes:
        if not self._fifo:
            return b""
        data = bytes(self._fifo)
        self._fifo.clear()
        return data

    def peek(self) -> bytes:
        return bytes(self._fifo)

    def consume(self, n: int) -> None:
        if n > 0:
            del self._fifo[:n]

    def write(self, data: bytes) -> None:
        self._fifo += self.console.feed(data)

    def caps(self) -> dict:
        return {"protocol": "uart", "channels": [], "verbs": ["scan", "uart"],
                "shape": "stream", "meta": {"port": "virtual-console"}}

    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        return [{"port": "virtual-console", "baud": 115200}]

    def close(self) -> None:
        pass


class VirtualConsoleBridge:
    """A running virtual bridge: bind a loopback port, serve the Console over the wire in a thread.
    Reached by the shipped `probe --backend virtual --target tcp://...` client."""

    backend = "virtual"

    def __init__(self, console: Console | None = None, host: str = "127.0.0.1"):
        self.medium = ConsoleMedium(console)
        self.server = BridgeServer(self.medium, host=host, port=0)
        self.port: int | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        self.port = self.server.bind()
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        name="virtual-console-bridge", daemon=True)
        self._thread.start()
        return self.port

    @property
    def target(self) -> str:
        return f"tcp://127.0.0.1:{self.port}"

    @property
    def env(self) -> dict:
        import os
        return dict(os.environ)

    def stop(self) -> None:
        self.server.close()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def __enter__(self) -> "VirtualConsoleBridge":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
