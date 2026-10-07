# Release wheel size budgets

Native wheel CI and publishing run `python scripts/ci/check_wheel_size.py --dist-dir native-dist`.
The check reports compressed download bytes, total unpacked payload bytes, each
native executable, and the ten largest compressed members. Unpacked payload size
excludes the Python interpreter, dependencies and bytecode generated at install time.

`budgets.json` defines explicit limits for each supported wheel platform. The
limits leave room for command-source additions while catching substantial package
growth. An unknown platform fails until its measured budget is added. Review
intentional budget increases alongside the package-size report; avoid increasing
limits solely to silence a failure. Source contributions do not need to include
generated files or run packaging checks locally.
