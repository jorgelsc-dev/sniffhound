#!/bin/sh
set -eu

export PYTHONPATH="/usr/lib/sniffhound/vendor${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 /usr/lib/sniffhound/launcher.py "$@"
