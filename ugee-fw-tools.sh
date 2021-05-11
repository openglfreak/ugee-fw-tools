#!/bin/sh

: "${script_dir:="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"}"

PYTHONPATH="${script_dir}${PYTHONPATH+:${PYTHONPATH}}" exec python3 -OO -m ugee_fw_tools ${1+"$@"}
