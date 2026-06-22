"""Live serial backend over a pty pair: the dual-purpose proof for UART, no hardware.

A pty pair is a real serial line from the OS point of view. A tiny UART device runs on the
master end; the SerialBackend drives the slave end with the same `uart read`/`uart write`
verbs the virtual lab uses.
"""

import os
import pty
import threading
import time

from espilon_probe.backends.serial import SerialBackend
from espilon_probe.protocols import uart

FLAG = "ESPILON{serial_pty_real}"


def _uart_device(master_fd: int):
    buf = b""
    while True:
        try:
            data = os.read(master_fd, 1024)
        except OSError:
            break
        if not data:
            break
        buf += data
        while b"\n" in buf:
            line, _, buf = buf.partition(b"\n")
            cmd = line.strip()
            if cmd == b"printenv":
                os.write(master_fd, b"bootcmd=run distro_bootcmd\nsecret=" + FLAG.encode() + b"\n")
            elif cmd == b"exit":
                return
            else:
                os.write(master_fd, b"unknown command\n")


def test_serial_pty_roundtrip():
    master, slave = pty.openpty()
    slave_path = os.ttyname(slave)
    t = threading.Thread(target=_uart_device, args=(master,), daemon=True)
    t.start()

    b = SerialBackend(slave_path)
    b.open()
    try:
        # banner/ordinary command leaks nothing
        uart.write(b, b"help\n")
        time.sleep(0.05)
        assert b"ESPILON{" not in uart.read(b)
        # the privileged command leaks the flag over the real line
        uart.write(b, b"printenv\n")
        time.sleep(0.05)
        assert FLAG.encode() in uart.read(b)
    finally:
        b.close()
        os.close(master)
        os.close(slave)
