FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:721650302bfda2f3832df73bb24aeacfa41c32e692f3d6e4dd06074e79c64ed7

COPY ./.clusterfuzzlite/requirements-atheris.txt $SRC/requirements-atheris.txt
RUN python3 -m pip install --require-hashes --no-cache-dir --no-binary=:all: --no-deps \
    -r $SRC/requirements-atheris.txt

COPY . $SRC/codex-plugin-scanner
WORKDIR $SRC/codex-plugin-scanner
COPY ./.clusterfuzzlite/build.sh $SRC/build.sh
