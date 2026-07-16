# espilon-probe developer tasks. Stdlib-only client; the bridges and conformance harness are
# pure-Python too, so nothing here needs hardware - a pty is kernel-provided.

PYTHON ?= python3
export PYTHONPATH := src

.PHONY: test conformance-uart conformance-can conformance-gatt conformance-gatt-real conformance build check

# Full unit + integration suite (includes the conformance gate).
test:
	$(PYTHON) -m pytest tests/ -q

# The UART fidelity gate: play the smoke tape against the virtual bridge AND the real (pty) bridge
# and diff. Prints the per-step comparison + the concatenated-RX equality; exits non-zero on drift.
# No hardware required.
conformance-uart:
	$(PYTHON) -m conformance.run conformance/tapes/uart_smoke.json

# Same diff against ACTUAL hardware: virtual (--backend virtual) vs a real board on TARGET, reached
# via the shipped `--backend serial` daemon (opened with --reset-on-open so the boot-only banner is
# captured; the mask-ROM boot log is dropped before comparing). Optionally set GARBLE to assert a
# wrong-baud read is garbled (real silicon only). Requires a flashed board (see
# conformance/hardware/uart-console-esp32/README.md).
#   make conformance-uart-real TARGET=/dev/ttyUSB0
#   make conformance-uart-real TARGET=/dev/ttyUSB0 GARBLE=57600
conformance-uart-real:
	@test -n "$(TARGET)" || { echo "usage: make conformance-uart-real TARGET=/dev/ttyUSB0 [GARBLE=57600]"; exit 2; }
	$(PYTHON) -m conformance.run --real-target $(TARGET) --real-baud $(or $(BAUD),115200) \
		$(if $(GARBLE),--garble-baud $(GARBLE),) conformance/tapes/uart_smoke.json

# The CAN FRAMED fidelity gate: play the UDS smoke tape against the virtual bridge AND the real
# vcan0 bridge (a genuine in-kernel SocketCAN stack + a separate UdsEcu responder) and diff the
# captured frames. vcan0 IS the real medium, so there is no separate `-real` target. Needs the `vcan`
# kernel module + a link; when vcan0 is absent this skips (exit 77, the automake skip code) with a
# setup hint rather than failing:
#   sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
conformance-can:
	$(PYTHON) -m conformance.run_can conformance/tapes/can_uds_smoke.json

# The BLE GATT TRANSACTION fidelity gate (CI): play the gatt smoke tape against the VIRTUAL bridge
# (GattServer behind the generic _serve_op path) through the shipped client and assert the tape. BLE
# has no software loopback, so - unlike UART/CAN - the CI gate is virtual-ONLY; needs nothing but
# stdlib (no bleak, no BlueZ, no hardware).
conformance-gatt:
	$(PYTHON) -m conformance.run_gatt --virtual-only conformance/tapes/gatt_smoke.json

# The GATED spot-check: virtual == the real AX201<->ESP32 leg. Needs the [hci] extra + a reflashed
# peripheral; skips (exit 77) with a setup hint when absent. NOT in the default `conformance`
# aggregate (it needs the board and the extra); the real-leg harness is a hardware-session follow-up.
conformance-gatt-real:
	$(PYTHON) -m conformance.run_gatt conformance/tapes/gatt_smoke.json

conformance: conformance-uart conformance-can conformance-gatt

# Build the wheel/sdist and validate the metadata.
build:
	$(PYTHON) -m build

check: build
	$(PYTHON) -m twine check dist/*
