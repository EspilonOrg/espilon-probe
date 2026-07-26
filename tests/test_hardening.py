"""Regression tests for the security-hardening splice.

These lock four fixes that guard the CLI/pcap surface against hostile or buggy backend input:

  - the `probe scan` table is HARD-bounded (row/column/per-cell caps) so a bridge returning a
    huge, key-heterogeneous result cannot build an O(rows x cols) matrix that OOMs/hangs;
  - scan cells are control-byte sanitized (C0/C1/DEL/ESC -> \\xHH) so an attacker-controlled
    field cannot forge a table row or inject terminal escapes;
  - `read_pcap` clamps a hostile per-record `caplen` BEFORE `f.read(caplen)`, so a 44-byte pcap
    that declares `caplen=0xffffffff` stops cleanly instead of attempting a ~4 GB allocation;
  - `_hex_value` refuses an empty payload (`spi write --hex 0x` no longer silently writes
    nothing) with a clean `ProbeError`.
"""

import struct
import time

import pytest

from espilon_probe import cli
from espilon_probe.core import frame as pframe
from espilon_probe.core.errors import ProbeError


# --- Fix A: scan table is aligned + hard-bounded, never a raw python dict ---

def test_scan_table_is_aligned_not_raw_dict():
    rows = [{"name": "MOCK-DEV", "addr": "AA:BB", "rssi": -40},
            {"name": "LOCK-7", "addr": "CC:DD:EE", "rssi": -72}]
    out = cli._scan_table(rows)
    lines = out.splitlines()
    assert lines[0].split() == ["name", "addr", "rssi"]
    assert lines[1].startswith("MOCK-DEV")
    assert "{" not in out and "'" not in out          # never a raw python dict dump


def test_scan_table_bounds_hostile_row_explosion():
    # A hostile/buggy bridge returning many rows each with a DISTINCT key made cols == rows, an
    # O(rows x cols) dense N^2 matrix that OOMs/hangs. The table must be HARD-bounded and fast.
    rows = [{f"k{i}": "v"} for i in range(3000)]
    t0 = time.perf_counter()
    out = cli._scan_table(rows)
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0                                  # no N^2 blow-up
    lines = out.splitlines()
    assert len(lines) <= cli._SCAN_MAX_ROWS + 3           # header + rows + two truncation notes
    assert len(lines[0].split()) <= cli._SCAN_MAX_COLS    # columns capped
    assert any("more rows (truncated)" in ln for ln in lines)
    assert any("more column(s) (truncated)" in ln for ln in lines)


def test_scan_table_caps_per_cell_work_independent_of_input_size():
    # `_scan_sanitize` used to run over the FULL cell before the cap slice, so one huge cell did
    # O(total-bytes) escaping. `_scan_cell` now truncates the raw cell BEFORE escaping.
    rows = [{"name": "A" * (10 * 1024 * 1024), "addr": "01", "rssi": -1}]
    t0 = time.perf_counter()
    out = cli._scan_table(rows)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.2                                  # bounded by the cap, not the input size
    assert ("A" * (cli._SCAN_MAX_CELL - 3) + "...") in out
    for ln in out.splitlines():
        for tok in ln.split():
            assert len(tok) <= cli._SCAN_MAX_CELL         # no cell wider than the cap


# --- Fix A (cont.): control-byte sanitize, no forged rows / terminal escapes ---

def test_scan_table_sanitizes_newline_no_forged_row():
    out = cli._scan_table([{"name": "evil\nffff  ZZ:ZZ  -1"}])
    lines = out.splitlines()
    assert len(lines) == 2                                # header + one data row, no forged row
    assert "\n" not in lines[1] and "\\x0a" in out        # the newline is shown escaped


def test_scan_table_sanitizes_ansi_no_raw_escape():
    out = cli._scan_table([{"name": "x\x1b[2K\rSPOOF"}])
    assert "\x1b" not in out and "\r" not in out          # no raw ESC / CR reaches the terminal
    assert "\\x1b" in out and "\\x0d" in out               # both are shown escaped


# --- Fix B: _hex_value accepts 0x prefix, refuses empty payload ---

def test_hex_value_rejects_empty_payload():
    # A bare prefix or a whitespace-only value decodes (via bytes.fromhex, which ignores ASCII
    # whitespace) to zero bytes and must be refused, not slip through a bare-string emptiness check.
    for bad in ("0x", "0X", "", "0x ", "  ", "0x\n", "0x\t"):
        with pytest.raises(ProbeError):
            cli._hex_value(bad, "spi write --hex")


def test_hex_value_accepts_prefix_and_bare():
    assert cli._hex_value("0xdeadbeef", "spi write --hex") == "deadbeef"
    assert cli._hex_value("deadbeef", "spi write --hex") == "deadbeef"
    zero = cli._hex_value("0x00", "spi write --hex")
    assert bytes.fromhex(zero) == b"\x00"                 # `0x00` is one real 0x00 byte, not empty


def test_hex_value_rejects_genuine_bad_hex():
    for bad in ("0xzz", "0x0", "gg"):
        with pytest.raises(ProbeError):
            cli._hex_value(bad, "spi write --hex")


# --- Fix C: read_pcap clamps a hostile caplen before allocating ---

def test_read_pcap_clamps_hostile_caplen(tmp_path):
    # A one-record pcap whose record declares caplen=0xFFFFFFFF (~4.3 GB) followed by only 4 bytes
    # must be treated as truncated/corrupt and stop cleanly, NEVER attempt a huge allocation.
    p = tmp_path / "hostile.pcap"
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147)
    rec = struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF) + b"\x00\x01\x02\x03"
    p.write_bytes(hdr + rec)
    dlt, frames = pframe.read_pcap(str(p))                # returns fast, no gigabyte allocation
    assert dlt == 147
    assert frames == []                                  # the over-ceiling record is dropped


def test_read_pcap_reads_valid_record(tmp_path):
    p = tmp_path / "ok.pcap"
    payload = b"\xde\xad\xbe\xef"
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147)
    rec = struct.pack("<IIII", 0, 0, len(payload), len(payload)) + payload
    p.write_bytes(hdr + rec)
    dlt, frames = pframe.read_pcap(str(p))
    assert dlt == 147
    assert frames == [payload]


def test_read_pcap_bad_magic_raises_probeerror(tmp_path):
    p = tmp_path / "junk.bin"
    p.write_bytes(b"this is definitely not a pcap file............")
    with pytest.raises(ProbeError):
        pframe.read_pcap(str(p))
