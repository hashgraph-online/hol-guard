FROM gcr.io/oss-fuzz-base/base-builder-python

COPY ./.clusterfuzzlite/requirements-atheris.txt $SRC/requirements-atheris.txt
RUN python3 -m pip install --no-cache-dir --no-binary=:all: --no-deps \
    -r $SRC/requirements-atheris.txt

COPY . $SRC/codex-plugin-scanner
WORKDIR $SRC/codex-plugin-scanner
COPY ./.clusterfuzzlite/build.sh $SRC/build.sh
