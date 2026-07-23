# probe demo GIFs

Terminal recordings of the `probe` CLI driven against a self-contained demo target.
Every frame is REAL `probe` output: each demo starts `demo_bridge.py` (a stdlib-only wire
target), exports `ESP_PROBE`, runs the commands, and stops the bridge. No real hardware and
no real flags: the "solve" target returns a demo-only `FLAG{...}` token, never a platform flag.

| GIF | Scenario | Shows |
|---|---|---|
| `demo-info.gif` | `probe --help` + `probe info` | the tool: full protocol + verb surface |
| `demo-scan-sniff.gif` | Zigbee target | `scan` a mesh, `sniff -c 8` to a real pcap, confirm the pcap |
| `demo-gatt.gif` | BLE smart-lock | `gatt enum` / `read` / `write` (unlock flips the state) |
| `demo-bus.gif` | SPI flash (W25Q128) | `spi id` (JEDEC), `spi read`, `spi dump` to a raw image |
| `demo-solve.gif` | BLE vault | scan, unlock over the protocol, secret handle returns a demo `FLAG{...}` token |

## Files

- `demo_bridge.py` - the demo target. Stdlib only; speaks the length-prefixed-JSON wire
  protocol (`core/wire.py`). `--scenario {info,zigbee,gatt,spi,solve} --port <port>`.
- `shell_setup.sh` - clean `probe-demo $` prompt + dark-friendly env, for the VHS path.
- `*.tape` - the canonical [VHS](https://github.com/charmbracelet/vhs) scripts.
- `render_agg.py` - the fallback renderer (asciinema cast + [agg](https://github.com/asciinema/agg)).

## Rendering

The GIFs in this folder were produced with the **agg fallback**: VHS drives `ttyd` + a
headless chromium, which the build sandbox refused to run; agg is pure Rust and needs no
browser. Both paths run the same commands and produce the same output.

Prereqs for either path: a venv with `probe` installed so the command resolves.

```bash
python3 -m venv .demo-venv
.demo-venv/bin/pip install -e .
export PATH="$PWD/.demo-venv/bin:$PATH"
```

### VHS (canonical)

Needs `vhs`, `ttyd`, and `ffmpeg` on `PATH`. From the repo root:

```bash
for t in demo/demo-*.tape; do vhs "$t"; done
```

### agg (fallback, used here)

Needs the `agg` binary; no browser. From the repo root:

```bash
python3 demo/render_agg.py --agg /path/to/agg            # all five
python3 demo/render_agg.py --agg /path/to/agg --only demo-gatt
```

`render_agg.py` starts/stops the bridge itself, captures real `probe` output, and writes
each `demo/<name>.gif` (dracula theme, ~1080px wide).
