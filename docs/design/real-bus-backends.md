# Real-hardware backends for SPI, I2C and JTAG (ftdi + openocd)

Status: spec, governed by `00-architecture.md`, `02-bridge-contract.md`. Grounded in
`backends/{serial,socketcan,hci}.py`, `bridges/{cli,server}.py`,
`bridges/media/{serial,socketcan}.py`, and `protocols/{spi,i2c,jtag}.py` as they stand on
`main`. No feature code here; this is the build spec.

## 0. Problem

`probe spi`, `probe i2c` and `probe jtag` work today only against the `virtual` backend (a
target server over the wire tunnel). There is no real adapter for any of the three. The
practical ESP32 challenges want to be dual-mode: a player either spawns the virtual instance
or points `probe` at a real ESP32 they own plus a common bench adapter, and runs the *same
verbs*. Two real backends close the gap:

- `ftdi`: real SPI + I2C master over a USB-FTDI adapter (FT232H / FT2232H) using `pyftdi`.
- `openocd`: real JTAG/SWD by bridging to an OpenOCD process.

The load-bearing constraint from `02-bridge-contract.md`: the client stays a generalist that
holds ZERO medium knowledge and ZERO third-party dependency. Every real backend is a thin
loopback launcher on the client side plus a bridge medium that owns the hardware I/O and its
one optional dependency, imported lazily. The client and the bridge meet only at
`core/wire.py`. Nothing below changes the wire, the CLI verb surface, the protocol modules, or
the Backend ABC.

## 1. The shape both backends already have to fit

The pattern is fixed by three shipped real backends and is not up for redesign:

```
CLIENT SIDE                          BRIDGE SIDE (subprocess, own deps)
probe --backend X                    python -m espilon_probe.bridges --medium X
  cli._make_backend(X) ->              bridges/cli._make_medium(X) ->
    backends/X.py (thin subclass        bridges/media/X.py  (owns the HW + lazy dep)
      of VirtualBackend)                  shape = "transaction"
      open(): _ensure_bridge(...)         op(verb, args) -> dict
      -> spawns/*discovers* a             open/close/apply_config/caps/scan/alive
      persistent daemon, connects
      over tcp://127.0.0.1:PORT
```

- `backends/X.py` is ~15 lines: subclass `VirtualBackend`, set `_transport_label`, override
  `open()` to call `_ensure_bridge(medium, endpoint, baud)` (the rendezvous machinery in
  `backends/serial.py`, already parameterised by medium name and reused verbatim by
  socketcan and hci), then `super().open()`. `close()` is inherited and does NOT kill the
  daemon. This is the whole client-side change per backend, and it introduces no new import
  in the client core.
- `bridges/media/X.py` is the real work. SPI, I2C and JTAG are all `shape = "transaction"`
  (see `protocols/spi.py`, `i2c.py`, `jtag.py` docstrings and `server._serve_op`). A
  transaction medium implements a single `op(verb, args) -> dict` that the generic
  `BridgeServer._serve_op` routes to; it also implements `open/close/apply_config/caps/scan/
  alive`. It does NOT implement `inject/take_frames/write/peek/consume` (those are packet /
  stream surfaces; `_serve_op` refuses relay verbs cleanly for a transaction medium).
- The third-party dependency (`pyftdi`, or the OpenOCD subprocess) is imported / spawned
  LAZILY inside the medium's `open()`, never at module import, so selecting the backend
  without the dependency fails with one clean actionable line and the client core never sees
  the import. This mirrors `bridges/media/hci.py` and the `[hci]` extra.

Why persistent (same rationale as serial/can/hci): the ESP32 must be held in a known state
(reset asserted for a flash-clip read; halted for JTAG memory reads) across the discrete
per-verb `probe` processes. A daemon that opened and tore down the adapter per verb would drop
that state between `probe jtag halt` and `probe jtag read`. The daemon keys on the target and
retires on idle timeout / medium death, exactly like the shipped three.

## 2. The `ftdi` backend (real SPI + I2C)

### 2.1 Files and selection

- New `src/espilon_probe/backends/ftdi.py`: `class FtdiBackend(VirtualBackend)`,
  `_transport_label = "ftdi"`. `open()` calls `_ensure_bridge("ftdi-spi" | "ftdi-i2c",
  endpoint, baud)` where the mode is chosen from the verb group the operator is running
  (`spi` -> `ftdi-spi`, `i2c` -> `ftdi-i2c`).
- New `src/espilon_probe/bridges/media/ftdi.py`: `SpiFtdiMedium` and `I2cFtdiMedium` (or one
  class with a `mode`), each `shape = "transaction"`, lazy `import pyftdi` in `open()`.
- `bridges/cli._make_medium`: add
  `if name == "ftdi-spi": from .media.ftdi import SpiFtdiMedium; return SpiFtdiMedium(endpoint, baud)`
  and the `ftdi-i2c` twin.
- `cli._make_backend`: add an `ftdi` branch. Because one FT232H MPSSE channel is physically
  wired for SPI OR I2C at a time (not both), the backend needs to know which mode to spawn.
  The verb group is already on `args` when `_make_backend` is called in `main()`. The minimal,
  additive change: pass the top-level verb into the factory and let `FtdiBackend` map it to a
  mode. Do NOT invent a `--mode` flag (the operator already typed `spi`/`i2c`; the UX note in
  the corpus is that daily use must stay light and flag-free).

```python
# cli._make_backend(name, target, baud, verb=None)   # verb added, used only by ftdi
if name == "ftdi":
    from .backends.ftdi import FtdiBackend
    return FtdiBackend(target, baud=baud, mode=_ftdi_mode(verb))  # verb in {spi,i2c,scan,info}
```

`scan`/`info` against `--backend ftdi` need a default mode: default to SPI (the flash-dump
demo is the headline), and let `probe --backend ftdi i2c scan` pick I2C via its verb. Document
that a bare `probe --backend ftdi scan` scans the SPI JEDEC id; `probe --backend ftdi i2c scan`
does the I2C address sweep.

Endpoint / target grammar (from `--target` or `$ESP_PROBE_TARGET`, same resolution as every
backend): a pyftdi URL, default `ftdi://ftdi:232h/1`. The medium passes it straight to
`pyftdi`'s controller `.configure(url)`. A frequency hint rides `apply_config` (see 2.4).

### 2.2 SPI operations (MPSSE master, `pyftdi.spi.SpiController`)

`op(verb, args)` for `SpiFtdiMedium`, mapping the existing `spi` verb ops (the protocol module
in `protocols/spi.py` is unchanged; it already routes every named transaction through
`backend.op` and does the client-side dump loop, bounds and pcap):

| op | args | MPSSE sequence (SPI NOR flash convention) | result dict |
|---|---|---|---|
| `spi.id` | `cs` | RDID `0x9F`, exchange, read 3 bytes | `{jedec_id, name}` |
| `spi.read` | `addr,len,cs` | READ `0x03` + 24-bit addr, read `len` (or fast-read `0x0B`+dummy) | `{data: hex}` |
| `spi.write` | `addr,data,cs` | WREN `0x06`; PP `0x02` + addr + bytes; poll WIP in SR1 until clear | `{ok, bytes}` |
| `spi.reg` | `name[,value],cs` | RDSR1 `0x05` / RDSR2 `0x35` read, or WREN + WRSR `0x01` write, by name | `{value: hex}` or `{ok}` |
| `spi.xfer` | `mosi,cs` | raw full-duplex `exchange(mosi, duplex=True)` | `{miso: hex}` |
| `scan` | - | = `spi.id`, flattened by `protocols/spi.scan_rows` | list row |

Result shapes must match what `protocols/spi.py` already reads: `spi.read` -> `res["data"]`
hex of exactly the requested length (the dump loop treats a short read as a hard error);
`spi.id` -> `res["jedec_id"]` int (or hex string) + optional `name`. The medium computes a
friendly `name` from the JEDEC manufacturer/device bytes with a tiny built-in table (Winbond
/ GigaDevice / Macronix common parts); an unknown id returns just the number. That table is
descriptive metadata about silicon, not challenge content, so it stays generalist.

pyftdi specifics: `SpiController().configure(url); port = ctrl.get_port(cs=cs, freq=..., mode=0)`;
`port.exchange(out, readlen, start=True, stop=True)`. CS is `args["cs"]` (default 0); flash
mode 0. Page-program respects the 256-byte page boundary (the medium splits a `spi.write`
crossing a page and issues one PP+poll per page); this is a device fact the medium owns, not
protocol logic.

### 2.3 I2C operations (`pyftdi.i2c.I2cController`)

`op(verb, args)` for `I2cFtdiMedium`, mapping the `i2c` verb ops (see the stranded branch,
section 6; `protocols/i2c.py` is likewise unchanged):

| op | args | I2C sequence | result dict |
|---|---|---|---|
| `i2c.scan` | - | sweep 7-bit addrs `0x03..0x77`, START+addr, note ACK | `{devices: [{addr, ack:true[, name][, size]}]}` |
| `i2c.read` | `addr,n[,reg]` | opt. write `reg` pointer (no stop), repeated-START, read `n` | `{data: hex}` |
| `i2c.write` | `addr,data[,reg]` | START, addr|W, opt reg, bytes, STOP | `{ok, bytes}` |
| `i2c.reg` | `name[,value]` | named-register read/write over the above | `{value}` or `{ok}` |
| `scan` | - | = `i2c.scan`, flattened by `protocols/i2c.scan_rows` | list rows |

pyftdi: `I2cController().configure(url, frequency=...); port = ctrl.get_port(addr)`;
`port.read(n)`, `port.write(data)`, `port.write_to(reg, data)`, `port.read_from(reg, n)`. The
address sweep uses `ctrl.poll(addr)` per address. `size` in a scan row is only populated when
the medium can identify a known EEPROM part (24Cxx family) by a probe; otherwise it is omitted
and `i2c dump` requires `--size` (the protocol module already refuses to guess an unbounded
length). Do NOT fabricate a size.

### 2.4 `apply_config` and `caps`

- `apply_config(config)`: honour a link setting sent in `HELLO.config`. For ftdi the useful
  one is bus frequency: `{"spi_hz": N}` / `{"i2c_hz": N}`. Applied before the first op; an
  absent / non-positive value keeps the medium default (SPI ~1-8 MHz for a clip read, I2C
  100 kHz). Never guessed.
- `caps()`: `{"protocol": "spi"|"i2c", "channels": [], "verbs": ["scan","spi"] | ["scan","i2c"],
  "shape": "transaction", "meta": {"url": ..., "freq": ..., "adapter": "ft232h"}}`. `verbs`
  advertises ONLY the mode's group so the client capability gate (`_require_verb`) refuses the
  other bus and the relay verbs automatically. This is the single truthful advertisement the
  whole gate rests on.
- `alive()`: `True` while the pyftdi controller is open and the device is present; `False`
  after a USB detach so the daemon retires (mirrors `SerialMedium.alive`). `scan()` returns
  the enumerate rows (JEDEC id for SPI, address sweep for I2C) so `probe scan` works even
  though the protocol modules also expose it through `op`.

### 2.5 Wiring the player needs

SPI flash dump of an ESP32 module (the headline demo):

- Adapter: FT232H breakout (Adafruit / generic), or an FT2232H.
- The ESP32-WROOM external flash is a SOIC-8 chip. Use a SOIC-8 test clip (Pomona / cheap
  clone) on the flash, or wire directly if the board breaks the pins out.
- FT232H `AD0=SCK -> CLK`, `AD1=MOSI -> DI`, `AD2=MISO -> DO`, `AD3=CS -> /CS`,
  plus 3V3 and GND. Do NOT back-power the whole board through the clip if the board is
  self-powered.
- Hold the ESP32 in reset (EN low) for the whole session so the SoC releases the flash bus and
  only the FT232H drives it. This is why the daemon is persistent: reset is asserted once and
  held across `spi id` -> `spi read` -> `spi dump`.
- Then: `probe --backend ftdi --target 'ftdi://ftdi:232h/1' spi id` to confirm the JEDEC id,
  then `probe --backend ftdi spi dump --addr 0 --len 0x400000 flash.bin`.

I2C (an EEPROM or a sensor on the ESP32's I2C bus, board powered, ESP idle):

- FT232H `AD0=SCL`, `AD1+AD2 tied = SDA` (MPSSE I2C needs SDA on two pins bridged), pull-ups
  to 3V3 (2.2k-4.7k) if the board lacks them, common GND.
- `probe --backend ftdi i2c scan`, then `probe --backend ftdi i2c dump --addr 0x50 eeprom.bin`.

These wiring notes live in the course, not in the client. The client prints nothing device
specific.

## 3. The `openocd` backend (real JTAG/SWD)

### 3.1 Bridge design: spawn + Tcl-RPC

OpenOCD is a long-lived process that opens the debug adapter and exposes command interfaces.
The medium OWNS an OpenOCD child and talks to it over its Tcl RPC port (default 6666), which is
the machine interface (the `\x1a`-terminated request/response protocol), NOT the human telnet
on 4444.

`bridges/media/openocd.py`, `OpenOcdMedium`, `shape = "transaction"`:

- `open()`: spawn `openocd -f <adapter.cfg> -f <target.cfg>` (or a single board cfg) with the
  Tcl RPC enabled on a chosen port; wait for the port to answer; open a persistent TCP socket
  to it. No third-party Python dependency: the Tcl-RPC framing (send command, read until
  `\x1a`) is ~20 lines of stdlib socket code, so the openocd backend adds NO pip dependency at
  all, only the `openocd` binary on PATH (declared as a runtime prerequisite, checked in
  `open()` with a clean "openocd not found on PATH" error).
- The medium does NOT parse OpenOCD's Tcl deeply. It sends one OpenOCD command per op and
  parses the specific line(s) it returns. Keep the surface tiny.
- `close()`: close the RPC socket, `shutdown` OpenOCD, reap the child.
- `alive()`: `True` while the child is running and the socket is open; `False` once OpenOCD
  exits (adapter unplugged), so the daemon retires.

Spawning OpenOCD inside the medium (not inside the thin client backend) keeps the client core
free of any process-management knowledge specific to OpenOCD, and lets the persistent-daemon
lifetime own the OpenOCD process lifetime as a unit.

### 3.2 JTAG op mapping (`protocols/jtag.py` unchanged)

| op | args | OpenOCD (Tcl-RPC) command | result dict |
|---|---|---|---|
| `jtag.scan_chain` | - | `scan_chain` (parse the TAP table) | `{taps: [{index,idcode,irlen,name}]}` |
| `jtag.idcode` | `tap` | from the parsed `scan_chain` / `targets` | `{idcode}` |
| `jtag.halt` | `tap` | `halt` | `{halted: true, pc?}` |
| `jtag.resume` | `tap[,addr]` | `resume [addr]` | `{resumed: true}` |
| `jtag.read` | `addr,words` | `read_memory <addr> 32 <words>` (returns a Tcl list) | `{words: [int,...]}` |
| `jtag.write` | `addr,word` | `write_memory <addr> 32 {<word>}` | `{ok: true}` |
| `jtag.reg` | `[name]` | `reg [name]` | `{regs: {...}}` or `{name, value}` |
| `scan` | - | = `jtag.scan_chain`, flattened by `jtag.scan_rows` | list rows |

`jtag.read` must return exactly `words` ints (`protocols/jtag.dump` treats a short read as a
hard error and does the chunked, bounded dump loop client-side, so the medium never dumps).
`read_memory ... 32 count` returns a whitespace-joined list of decimal words; the medium parses
that to the `words` list. A target that is not halted refuses a memory read: surface OpenOCD's
error as a normal `{error: ...}` result dict (a protocol-level error, not a Python exception),
so the client renders it deterministically, matching how the BLE medium returns ATT errors.

### 3.3 Adapter + target config

Ship a small, generalist set of OpenOCD config fragments under a data dir in the bridge (these
describe silicon and adapters, not challenges, so they are generalist and belong on the bridge
side):

- Adapters: `esp-usb-jtag` (the ESP32-S3/C3 built-in USB JTAG), `ftdi/esp-prog`, `jlink`,
  `cmsis-dap`. Most already ship with OpenOCD; prefer referencing the installed
  `interface/*.cfg` over vendoring.
- Targets: `esp32`, `esp32s3`, `esp32c3`. Espressif's OpenOCD ships `board/esp32-*.cfg` and
  `board/esp32s3-builtin.cfg`; reference those by name.
- Endpoint grammar: `--target esp32s3` selects the target cfg; the adapter defaults per target
  (built-in USB JTAG for S3/C3) or is overridable as `--target 'esp32:jlink'`. The medium maps
  the endpoint to `-f interface/<adapter>.cfg -f target/<target>.cfg`. Keep the mapping a small
  Python dict, not a config DSL.

### 3.4 Wiring the player needs

- ESP32-S3 / ESP32-C3: the built-in USB-serial-JTAG peripheral needs only the USB cable; no
  external probe. `probe --backend openocd --target esp32s3 scan` should list the TAP.
- Classic ESP32 (no built-in JTAG): an external JTAG adapter (ESP-Prog / FT2232H, or J-Link)
  on TMS/TCK/TDI/TDO/GND, with the strapping that enables JTAG (not fused off). Course-level
  detail.
- Then `probe --backend openocd --target esp32s3 jtag halt`, `... jtag read --addr 0x3fc80000
  --words 64`, `... jtag dump --addr <sram> --len <n> mem.bin`.

## 4. Backend-selection and capability model (no CLI redesign)

Selection is already uniform and does not change:

- `--backend ftdi|openocd`, or `$ESP_PROBE_BACKEND`, or a `probe use` default, resolved by the
  existing precedence in `cli._resolve_backend` (`--backend` > `$ESP_PROBE_BACKEND` > config >
  `virtual`). Target from `--target` > `$ESP_PROBE_TARGET` > config; the virtual backend alone
  falls back to `$ESP_PROBE`.
- `_make_backend` gains two branches (`ftdi`, `openocd`) exactly like the shipped three, and
  drops both names from the "not implemented yet" `SystemExit` list. The one additive touch is
  passing the verb group to the factory so `ftdi` can pick SPI vs I2C mode (section 2.1).

Capability model, unchanged and already sufficient for "no real backend available":

1. The medium advertises `verbs` truthfully in `caps()`. `_require_verb` (the single gate,
   convention C1) refuses any verb the active backend did not advertise, cleanly and before
   routing. So `probe --backend ftdi jtag halt` fails with
   `'halt' is not supported on protocol 'spi' (supported: scan, spi)` - a real backend that
   does not do JTAG simply never advertises it.
2. A backend name with no adapter present: the lazy dependency / binary check in the medium's
   `open()` fails, the bridge child exits before announcing its port, and
   `backends/serial._spawn_daemon` already raises a clean
   `"loopback ftdi bridge for ... exited before announcing"`. Improve the signal by having the
   medium print one actionable line to stderr on the missing dep / binary (`pyftdi not
   installed: pip install 'espilon-probe[ftdi]'` / `openocd not found on PATH`) before exiting
   1; the launcher surfaces the nonzero exit.
3. A protocol with no real backend at all (e.g. asking a real backend for a bus it cannot do)
   is the same gate as (1). There is no new "capability negotiation" layer; the truthful
   `caps().verbs` list plus `_require_verb` is the whole mechanism, identical to how hci
   advertises only `["scan","gatt"]`.

Add the pip extra in `pyproject.toml`, mirroring `[hci]`:

```
ftdi = ["pyftdi>=0.55"]   # real SPI/I2C master (lazy import in bridges/media/ftdi.py only)
# openocd needs no python dep; it shells out to the `openocd` binary (declared prerequisite).
```

## 5. Faithfulness and safety

### 5.1 What must be real vs simulated

Everything below the wire on a real backend is real silicon: real MPSSE clocking, real flash
JEDEC id and contents, real I2C ACK/NACK, real TAP idcodes and memory. The medium simulates
NOTHING; if it cannot do an op it returns a clean error, it never fabricates a plausible
result (that would be the "careless author" failure the corpus warns about, one layer down).
The `name` lookups (SPI JEDEC part name, known-EEPROM size) are descriptive metadata only and
must degrade to "unknown / omitted" rather than guess.

The virtual/real symmetry is the point: the same `probe spi dump` bytes come back whether the
target is the virtual model or a real clip, so a course can be authored once and run either
way. The one honest divergence to document: timing and flakiness are real on hardware (a bad
clip contact yields a read error, not a silent zero-fill), and the medium must surface those as
errors.

### 5.2 Destructive-op guards

The generalist bus writes are recoverable and need no hard gate, but two of them can brick a
board, so they warrant a soft confirm on a REAL backend only:

- `spi.write` to a real flash can overwrite a bootloader (recoverable only by re-flashing).
- `jtag.write` is volatile memory (recoverable by reset). `i2c.write` is generally recoverable.

The IRREVERSIBLE ops are the ESP32 eFuse burns, which are write-once and monotonic in real
silicon and can permanently lock or brick the chip:

- `esp burn-key`, `esp burn-efuse`, `esp read-protect` (RD_DIS). These are already in the CLI
  (`cli.py` ~1060) and route straight to the backend with NO confirmation. Against the virtual
  backend that is fine (the model resets). There is NO real `esp` backend in this task's scope,
  but this spec flags the guard as a HARD PREREQUISITE that must land together with any real
  download-mode backend, because a real burn is permanent.

Recommended guard (specify now, implement with the real esp backend; keep it minimal, no DSL):

- A single predicate in the CLI: `is_real = backend_transport != "virtual"`. For the
  irreversible verbs (`esp burn-key|burn-efuse|read-protect`) on a real backend, require an
  explicit `--yes` AND, for eFuse burns, an interactive confirmation that echoes the exact
  field/block being burned (skippable with `--yes` for scripted use, but `--yes` must be typed;
  never defaulted). Refuse loud without it. Do NOT add a guard on the virtual backend (it would
  break the labs' non-interactive flow, Model B).
- For `spi.write` on a real ftdi backend, a one-line stderr warning naming the target address
  range plus a `--yes` gate is sufficient (recoverable, so no interactive echo). Keep `jtag.
  write` / `i2c.write` unguarded (recoverable, high-frequency during real work).

The guard lives in the CLI (it is operator-safety UX, and the CLI already owns the transport
label), NOT in the medium, so the wire and the bridge stay generalist.

## 6. Landing plan for the stranded `plugsmith/i2c-protocol` branch

State (measured): one commit `5763973` on top of `main` (`3af8da5`), which is identical to
`github/main`. Diffstat: `protocols/i2c.py` (+218), `cli.py` (+65, the i2c parser + dispatch),
`core/frame.py` (+3, `DLT_USER_PROBE_I2C = 151`), `protocols/__init__.py` (+1 registration),
`tests/test_i2c.py` (+366), `DEVLOG.md` (+35). `i2c.py` is confirmed absent on both `main` and
`github/main`. The branch is unpushed to `github`.

Mergeability: it is PURELY ADDITIVE. It adds a new protocol module, a new verb group, and a new
DLT constant; it touches no existing protocol's behaviour. Its parent IS `origin/main`, so it
fast-forwards cleanly today (this will stay true only until `main` moves; re-check the base
before landing). It is virtual-only: `i2c.py` routes every op through `backend.op`, so it works
against the virtual backend immediately and against the real `ftdi` I2C medium once section 2.3
lands. Landing it now unblocks the pilot's I2C stage on virtual and stops the branch bit-rotting
against a moving `main`.

Sequence (I do NOT push or merge this branch; this is the plan for the maintainer):

1. Re-verify the base: `git merge-base --is-ancestor origin/main plugsmith/i2c-protocol` and
   that the branch parent still equals `origin/main`. If `main` moved, rebase the one commit.
2. Check the DLT does not collide: confirm `151` is unused by any other protocol in
   `core/frame.py` on current `main` (it was free at survey time).
3. Run the suite: `python3 -m pytest tests/ -q`, and specifically `tests/test_i2c.py`,
   `tests/test_capabilities_shape.py`, `tests/test_cli_verbs.py`, `tests/test_adversarial_audit.py`
   (the last asserts every verb group's gate/shape). All must pass on the branch.
4. Push the branch to `github` and open a PR through `gh pr create` for review. This repo is on
   GitHub, so the GitLab `git push -o merge_request.create` footgun does not apply here; do not
   use it regardless. A human reviewer merges; no self-merge.
5. After merge, the `ftdi` I2C medium (section 2.3) targets the now-landed `i2c` verb surface.

## 7. Build increment order

Ship in the order of proof value, smallest real path first:

1. **FT232H SPI read path (first proof).** `bridges/media/ftdi.py` SPI mode with just
   `spi.id` + `spi.read` + `scan`, `backends/ftdi.py`, the `_make_backend`/`_make_medium`
   wiring, the `[ftdi]` extra. Prove it with `probe --backend ftdi spi id` and a real
   `probe --backend ftdi spi dump` of an ESP32 flash over a SOIC-8 clip. This is the
   highest-value demo (flash extraction) and exercises the whole path end to end with the
   least code. `spi.write`/`spi.reg`/`spi.xfer` follow once read is proven.
2. **FTDI I2C.** Land the `i2c` branch (section 6) first, then add the I2C mode to
   `bridges/media/ftdi.py` (`i2c.scan` + `i2c.read` + dump; then `i2c.write`/`i2c.reg`). Demo:
   scan + EEPROM dump.
3. **Guarded writes.** `spi.write` with the real-backend `--yes` soft guard (section 5.2).
4. **openocd JTAG.** `bridges/media/openocd.py`: spawn + Tcl-RPC, then `scan_chain`/`idcode`/
   `halt`/`resume`/`read` + the client-side `dump`; `jtag.write` last. Demo on an ESP32-S3
   built-in USB-JTAG (no external probe), then a classic ESP32 with an external adapter.
5. **esp burn guards.** Only if/when a real download-mode `esp` backend is scoped: land the
   irreversible-op confirmation (section 5.2) in the SAME change, never after.

## 8. Test strategy

- Unit, no hardware (the bulk): drive each medium's `op()` against a FAKE transport. For ftdi,
  inject a fake pyftdi `SpiController`/`I2cController` (a stub exposing `exchange`/`read`/
  `write`/`poll`) and assert the exact MPSSE byte sequences (RDID `0x9F`, READ `0x03`+addr,
  WREN+PP+WIP poll, the I2C address sweep) and the result-dict shapes the protocol modules
  require (`spi.read` returns exactly `len` bytes; a short read is a hard error). For openocd,
  a fake Tcl-RPC server socket that returns canned `scan_chain` / `read_memory` strings; assert
  the command strings sent and the parsed `words`/`taps`. These run in CI with no adapter.
- Wire-shape conformance: extend the existing `tests/test_capabilities_shape.py` /
  `test_adversarial_audit.py` style so each new medium advertises `shape == "transaction"`,
  the correct `verbs`, and refuses relay verbs (`sniff/inject/replay`) and the other bus's
  verbs through the gate. Prove the gate is real by asserting `probe --backend ftdi jtag halt`
  and `probe --backend ftdi spi ... ` with a wrong verb both exit nonzero with the C1 message.
- Bridge round-trip: reuse the pty/loopback harness pattern (`tests/_mock_bridge.py`,
  `conformance/`) to run a real `probe-bridge --medium ftdi-spi` against the fake pyftdi
  controller over a real socket, exercising the persistent-daemon rendezvous
  (`_ensure_bridge`) unchanged.
- Negative proof for the guards: plant a real-transport label, assert an eFuse burn without
  `--yes` refuses (exit nonzero, nothing sent to the backend), and that the virtual backend is
  NOT gated (the labs' non-interactive path still works). This follows the corpus rule that a
  new gate must be shown to go red before it is trusted.
- Hardware smoke (manual, documented, not in CI): the two demos in 2.5 / 3.4 against a real
  FT232H + ESP32 module and an ESP32-S3, recorded once per adapter as the real-device
  conformance note (mirroring the existing UART real-device conformance run).
