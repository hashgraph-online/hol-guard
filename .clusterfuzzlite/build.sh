#!/bin/bash -eu

cd "$SRC/ai-plugin-scanner"
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"

for fuzzer in fuzzers/*_fuzzer.py; do
  compile_python_fuzzer "$fuzzer"
done
