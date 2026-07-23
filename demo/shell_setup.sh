#!/bin/bash
# Clean, quiet prompt + dark-friendly env for the probe demo recordings.
CYAN='\[\033[36m\]'
DIM='\[\033[2m\]'
RESET='\[\033[0m\]'
export PS1="${CYAN}probe-demo${RESET} ${DIM}\$${RESET} "
# Keep the venv active but hide its noise from the prompt.
export VIRTUAL_ENV_DISABLE_PROMPT=1
export ESP_PROBE_TIMEOUT=10
# No pager / no color surprises.
export PAGER=cat
export TERM=xterm-256color
clear
