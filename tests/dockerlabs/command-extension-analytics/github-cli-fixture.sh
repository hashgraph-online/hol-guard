#!/bin/sh
set -eu

if [ "$#" -eq 2 ] && [ "$1" = "api" ] && [ "$2" = "user" ]; then
  printf '%s\n' '{"login":"dashboard-reviewer"}'
  exit 0
fi

printf '%s\n' 'offline GitHub fixture rejected non-viewer invocation' >&2
exit 97
