"""Partition the MCP matrix while retaining reuse of each package admission."""

PackageCase = tuple[str, str, str, str, str]


def package_case_batches(cases: list[PackageCase]) -> list[list[PackageCase]]:
    if not cases:
        raise ValueError("the bundled MCP matrix must contain package cases")
    packages: dict[str, list[PackageCase]] = {}
    for case in cases:
        packages.setdefault(case[0], []).append(case)
    batches: list[list[PackageCase]] = [[] for _ in range(min(64, len(packages)))]
    for package in packages.values():
        min(batches, key=len).extend(package)
    return batches
