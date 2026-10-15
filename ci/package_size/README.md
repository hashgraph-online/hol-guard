# Release wheel size budgets

The nightly native workflow and publishing run `python scripts/ci/check_wheel_size.py --dist-dir native-dist`.
The active CI lane also checks native executable budgets on its existing build
with `--native-dir rust/target/release --platform manylinux_2_17_x86_64`; this
adds no compilation and does not claim wheel download-size coverage.
The check reports compressed download bytes, total unpacked payload bytes, each
native executable, and the ten largest compressed members. Unpacked payload size
excludes the Python interpreter, dependencies and bytecode generated at install time.

`budgets.json` defines explicit limits for each supported wheel platform. The
limits leave room for command-source additions while catching substantial package
growth. An unknown platform fails until its measured budget is added. Review
intentional budget increases alongside the package-size report; avoid increasing
limits solely to silence a failure. Source contributions do not need to include
generated files or run packaging checks locally.

Repairing an immutable release whose source predates this checker retains the
older release's behavior. Publishing skips the new check only when the validated
release-repair path checks out such a source. New releases and native-wheel CI
always enforce their platform budgets.

## Alpha prerelease allowance

Alpha native wheels are built with fast per-crate codegen (no link-time
optimization, 16 codegen units) so the alpha publish path finishes sooner. Their
binaries are larger by design, and they are published only as GitHub prerelease
assets and to TestPyPI, never to PyPI. `alpha-native-budgets.json` holds their
separate ceiling (2 times the standard native budgets), applied with
`check_wheel_size.py --alpha-native-budgets`. The checker refuses that option for
any version that is not a canonical alpha, never applies it to the pure
`py3-none-any` wheel, and stable and canary wheels keep `budgets.json`.
