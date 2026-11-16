"""The read-only ``docker`` stand-in the realism fixture installs.

It answers the manifest-query and log-read shapes the gate's cases run and
nothing else: it never reaches a registry or a daemon. The Python copy beside
it is what the Windows launcher runs, so both see the same argv.
"""

from __future__ import annotations

import shlex

DOCKER_DIGEST = "sha256:" + "0123456789abcdef" * 4
DOCKER_LOG_LINES = (
    "2026-01-07T09:14:02.118374021Z listening on :8080",
    "2026-01-07T09:14:03.402915774Z GET /healthz 200 1ms",
    "2026-01-07T09:14:11.771206339Z GET /api/items 200 23ms",
)
DOCKER_CONTEXT_CURRENT = "default"
DOCKER_CONTEXT_NAMES = ("default", "desktop-linux")
DOCKER_CONTEXT_TABLE = (
    "NAME            DESCRIPTION                               DOCKER ENDPOINT",
    "default *       Current DOCKER_HOST based configuration   unix:///var/run/docker.sock",
    "desktop-linux   Docker Desktop                            unix:///var/run/docker.sock",
)
DOCKER_LOG_LINES_SHELL = " ".join(shlex.quote(line) for line in DOCKER_LOG_LINES)
DOCKER_CONTEXT_NAMES_SHELL = " ".join(shlex.quote(name) for name in DOCKER_CONTEXT_NAMES)
DOCKER_CONTEXT_TABLE_SHELL = " ".join(shlex.quote(row) for row in DOCKER_CONTEXT_TABLE)
DOCKER_STUB = (
    "#!/bin/sh\n"
    "# Read-only stand-in for docker: it never reaches a registry or a daemon.\n"
    "# Only the options Guard admits for a manifest query are understood.\n"
    'if [ "${1:-}" = buildx ] && [ "${2:-}" = imagetools ] && [ "${3:-}" = inspect ]; then\n'
    "  shift 3\n"
    "  images=0\n"
    '  while [ "$#" -gt 0 ]; do\n'
    '    case "$1" in\n'
    "      --raw | --format=*) ;;\n"
    '      --format) [ "$#" -ge 2 ] || exit 2; shift ;;\n'
    "      -*) printf 'docker stand-in: unsupported option\\n' >&2; exit 2 ;;\n"
    "      *) images=$((images + 1)) ;;\n"
    "    esac\n"
    "    shift\n"
    "  done\n"
    '  [ "$images" -eq 1 ] || exit 2\n'
    f"  printf '{DOCKER_DIGEST}\\n'\n"
    "  exit 0\n"
    "fi\n"
    'if [ "${1:-}" = container ] && [ "${2:-}" = logs ]; then\n'
    "  shift\n"
    "fi\n"
    'if [ "${1:-}" = logs ]; then\n'
    "  shift\n"
    "  names=0\n"
    '  while [ "$#" -gt 0 ]; do\n'
    '    case "$1" in\n'
    "      -t | --timestamps | --details) ;;\n"
    "      --tail=* | --since=* | --until=*) ;;\n"
    '      --tail | --since | --until) [ "$#" -ge 2 ] || exit 2; shift ;;\n'
    "      -*) printf 'docker stand-in: unsupported option\\n' >&2; exit 2 ;;\n"
    "      *) names=$((names + 1)) ;;\n"
    "    esac\n"
    "    shift\n"
    "  done\n"
    '  if [ "$names" -ne 1 ]; then\n'
    "    printf 'docker stand-in: unsupported command\\n' >&2\n"
    "    exit 2\n"
    "  fi\n"
    f"  printf '%s\\n' {DOCKER_LOG_LINES_SHELL}\n"
    "  exit 0\n"
    "fi\n"
    'if [ "${1:-}" = context ]; then\n'
    "  shift\n"
    '  if [ "${1:-}" = show ] && [ "$#" -eq 1 ]; then\n'
    f"    printf '{DOCKER_CONTEXT_CURRENT}\\n'\n"
    "    exit 0\n"
    "  fi\n"
    '  if [ "${1:-}" = ls ]; then\n'
    "    shift\n"
    "    quiet=0\n"
    '    while [ "$#" -gt 0 ]; do\n'
    '      case "$1" in\n'
    "        -q | --quiet) quiet=1 ;;\n"
    "        --format=*) ;;\n"
    '        --format) [ "$#" -ge 2 ] || exit 2; shift ;;\n'
    "        *) printf 'docker stand-in: unsupported option\\n' >&2; exit 2 ;;\n"
    "      esac\n"
    "      shift\n"
    "    done\n"
    '    if [ "$quiet" -eq 1 ]; then\n'
    f"      printf '%s\\n' {DOCKER_CONTEXT_NAMES_SHELL}\n"
    "    else\n"
    f"      printf '%s\\n' {DOCKER_CONTEXT_TABLE_SHELL}\n"
    "    fi\n"
    "    exit 0\n"
    "  fi\n"
    "fi\n"
    "printf 'docker stand-in: unsupported command\\n' >&2\n"
    "exit 2\n"
)
DOCKER_STUB_PYTHON = f"""\
import sys

args = sys.argv[1:]


def fail():
    sys.stderr.buffer.write(b'docker stand-in: unsupported command\\n')
    raise SystemExit(2)


def emit(lines):
    sys.stdout.buffer.write(('\\n'.join(lines) + '\\n').encode())
    raise SystemExit(0)


def operands(words, flags, valued):
    # The non-option words, or None when an option this stand-in does not take appears.
    names, index = [], 0
    while index < len(words):
        word = words[index]
        index += 1
        if word in flags or any(word.startswith(name + '=') for name in valued):
            continue
        if word in valued:
            if index >= len(words):
                return None
            index += 1
            continue
        if word.startswith('-'):
            return None
        names.append(word)
    return names


if args[:3] == ['buildx', 'imagetools', 'inspect']:
    images = operands(args[3:], {{'--raw'}}, {{'--format'}})
    if images is None or len(images) != 1:
        fail()
    emit(['{DOCKER_DIGEST}'])

if args[:2] == ['container', 'logs']:
    args = args[1:]

if args[:1] == ['logs']:
    containers = operands(
        args[1:],
        {{'-t', '--timestamps', '--details'}},
        {{'--tail', '--since', '--until'}},
    )
    if containers is None or len(containers) != 1:
        fail()
    emit({list(DOCKER_LOG_LINES)!r})

if args[:2] == ['context', 'show'] and len(args) == 2:
    emit(['{DOCKER_CONTEXT_CURRENT}'])

if args[:2] == ['context', 'ls']:
    rest = args[2:]
    quiet = '-q' in rest or '--quiet' in rest
    if operands([word for word in rest if word not in ('-q', '--quiet')], set(), {{'--format'}}) != []:
        fail()
    emit({list(DOCKER_CONTEXT_NAMES)!r} if quiet else {list(DOCKER_CONTEXT_TABLE)!r})

fail()
"""
