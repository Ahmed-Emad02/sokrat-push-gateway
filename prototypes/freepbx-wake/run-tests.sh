#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONDONTWRITEBYTECODE=1
python3 "$DIR/test/runtime_test.py"
if command -v php >/dev/null 2>&1; then
    php "$DIR/test/generator.php" 16
    php "$DIR/test/generator.php" 17
elif [ -n "${PHP_TEST_IMAGE:-}" ]; then
    docker run --rm --network none --mount "type=bind,src=$DIR,dst=/prototype,readonly" --entrypoint php "$PHP_TEST_IMAGE" /prototype/test/generator.php 16
    docker run --rm --network none --mount "type=bind,src=$DIR,dst=/prototype,readonly" --entrypoint php "$PHP_TEST_IMAGE" /prototype/test/generator.php 17
else
    echo 'PHP is required; alternatively set PHP_TEST_IMAGE to a locally available image containing PHP.' >&2
    exit 1
fi
