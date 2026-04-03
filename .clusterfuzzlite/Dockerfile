FROM gcr.io/oss-fuzz-base/base-builder-python

RUN python3 -m pip install --no-cache-dir --no-binary=:all: --no-deps \
    "atheris==3.0.0" \
    --hash=sha256:1f0929c7bc3040f3fe4102e557718734190cf2d7718bbb8e3ce6d3eb56ef5bb3

COPY . $SRC/codex-plugin-scanner
WORKDIR $SRC/codex-plugin-scanner
COPY ./.clusterfuzzlite/build.sh $SRC/build.sh
