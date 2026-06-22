# Roadmap

The goal: a clean, public, pip-installable physical-layer tool (GitHub + PyPI) plus a
private catalogue of probe-backed labs on learn.espilon.net. Public tool, private content.

## Done (v0.1, local)

- Core: wire protocol, virtual backend, CLI, pcap, Backend contract. Hardened, reviewed
  twice adversarially. 25 tests + 6 lab smoke/adversarial, green.
- Four protocols virtual: BLE, CAN, Zigbee, UART.
- One real backend coded: socketcan (raw PF_CAN).
- Six labs under `labs/`, all green, course-iso, solved through the real `probe` CLI.
- GPL-3.0, GitHub Actions CI, packaging at 0.1.0.

## Phase 1 - Finish the tool (local, no outward action)

- `serial` backend (UART over a pty pair): a second real backend provable locally, no
  hardware. Live test like socketcan.
- socketcan live: prove the loopback once a `vcan0` exists
  (`sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0`).
- Exhaustive CLI pass: drive EVERY flag of every lab through the real `probe` (not just one
  path per lab).
- Optional polish: uart-aware scan formatter; the minor pedagogy nits from review.

## Phase 2 - Prep for GitHub (local, nothing pushed)

- DEVLOG -> clean git history (Conventional Commits, no third-party attribution).
- README for GitHub: CI badge, PyPI install, quickstart, labs overview, hardware-backend
  transfer note.
- CONTRIBUTING + a RELEASE checklist. Tag 0.1.0.

## Phase 3 - Publish (GATED, explicit go per item)

- Create the GitHub repo (public) and push.
- Publish to PyPI so players `pip install espilon-probe`.

## Phase 4 - Dockerize the labs (local, no outward action)

- Per lab: `target/Dockerfile` (vendor probe from the repo + the device + a bridge
  entrypoint on the probe port), `compose.yaml` (target exposed + tester QA), `challenge.yml`
  (kind:lab, learn_slug, expose port, test_in_service: tester, flags).
- Start with one gabarit (uart-bootloader), then the six.

## Phase 5 - Learn integration (private, prod)

- `_lab_panel.html`: render the dynamic `ESP_PROBE` endpoint per spawn.
- `seed_lab` adapter ingests a probe `challenge.yml` into a `learn_labs` row.
- Courses into `learn_lesson_translations[en]`.
- Reachability: raw TCP per session from the player's own machine (decision: public port /
  VPN / proxy). Shared with all Model B labs.

## Phase 6 - Prod rollout (GATED, explicit go per item)

- Build images on the prod dockerd, spawn, solve externally with `probe`, run smoke +
  adversarial in the tester, Pony Tail blind.
- Open per lab.

## Open decisions

- GitHub public vs private (leaning public).
- PyPI public vs private index.
- Reachability mechanism (public port / VPN / proxy).
- Launch with the 6 probe labs, or add 3-4 container challenges first to vary the catalogue.

## What can run now vs gated

- Local now, no outward action: Phase 1 (serial pty), Phase 2 (git prep + README), Phase 4
  (dockerize).
- Gated on an explicit go: Phase 3 (push GitHub + publish PyPI), Phase 6 (prod deploy).
