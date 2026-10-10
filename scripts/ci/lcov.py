"""Merge verified LCOV records without dropping uncovered sources or branches."""

from pathlib import Path


def counter(value: str) -> int:
    number = int(value)
    if number < 0:
        raise ValueError("LCOV counter is negative")
    return number


def merge(paths: list[Path]) -> str:
    sources = {}
    for path in paths:
        current = None
        record_definitions = set()
        record_counters = set()
        with path.open(encoding="utf-8") as handle:
            for raw in handle:
                line = raw.rstrip("\n\r")
                if line.startswith("SF:"):
                    if current is not None:
                        raise ValueError("LCOV source record is incomplete")
                    current = sources.setdefault(
                        line[3:], {"lines": {}, "functions": {}, "function_hits": {}, "branches": {}}
                    )
                    record_definitions = set()
                    record_counters = set()
                elif line == "end_of_record":
                    if current is None:
                        raise ValueError("LCOV record has no source")
                    if not record_counters <= record_definitions:
                        raise ValueError("LCOV function counter has no definition in its source record")
                    current = None
                elif not line or line.startswith("TN:"):
                    continue
                else:
                    if current is None:
                        raise ValueError("LCOV counter has no source")
                    kind, value = line.split(":", 1)
                    if kind == "DA":
                        fields = value.split(",")
                        if len(fields) not in {2, 3}:
                            raise ValueError("LCOV line counter is invalid")
                        number, hits = int(fields[0]), counter(fields[1])
                        if number <= 0:
                            raise ValueError("LCOV line number is invalid")
                        checksum = fields[2] if len(fields) == 3 else None
                        previous_hits, previous_checksum = current["lines"].get(number, (0, None))
                        if checksum is not None and previous_checksum not in {None, checksum}:
                            raise ValueError("LCOV line checksums conflict")
                        current["lines"][number] = (previous_hits + hits, previous_checksum or checksum)
                    elif kind == "FN":
                        start, name = value.split(",", 1)
                        start = int(start)
                        end = None
                        possible_end, separator, possible_name = name.partition(",")
                        if separator and possible_end.isdecimal():
                            end, name = int(possible_end), possible_name
                        if start <= 0 or not name or (end is not None and end < start):
                            raise ValueError("LCOV function definition is invalid")
                        previous = current["functions"].get(name)
                        if previous is not None:
                            if previous[0] != start or (previous[1] is not None and end not in {None, previous[1]}):
                                raise ValueError("LCOV function definitions conflict")
                            end = previous[1] if previous[1] is not None else end
                        current["functions"][name] = (start, end)
                        record_definitions.add(name)
                    elif kind == "FNDA":
                        hits, name = value.split(",", 1)
                        if not name:
                            raise ValueError("LCOV function counter has no name")
                        current["function_hits"][name] = current["function_hits"].get(name, 0) + counter(hits)
                        record_counters.add(name)
                    elif kind == "BRDA":
                        number, block, branch, hits = value.split(",")
                        number = int(number)
                        if number <= 0 or not block or not branch:
                            raise ValueError("LCOV branch identity is invalid")
                        key = (number, block, branch)
                        hits = None if hits == "-" else counter(hits)
                        previous = current["branches"].get(key)
                        current["branches"][key] = (
                            None if hits is None and previous is None else (previous or 0) + (hits or 0)
                        )
                    elif kind not in {"LF", "LH", "FNF", "FNH", "BRF", "BRH"}:
                        raise ValueError(f"Unsupported LCOV field: {kind}")
        if current is not None:
            raise ValueError("LCOV source record is incomplete")
    if not sources:
        raise ValueError("LCOV merge has no sources")
    output = []
    for source, data in sorted(sources.items()):
        if data["function_hits"].keys() - data["functions"].keys():
            raise ValueError("LCOV function counter has no definition")
        output.append(f"SF:{source}")
        for name, (start, end) in sorted(data["functions"].items(), key=lambda item: (item[1][0], item[0])):
            location = str(start) if end is None else f"{start},{end}"
            output.append(f"FN:{location},{name}")
        for name in sorted(data["functions"]):
            output.append(f"FNDA:{data['function_hits'].get(name, 0)},{name}")
        output.extend(
            [f"FNF:{len(data['functions'])}", f"FNH:{sum(hits > 0 for hits in data['function_hits'].values())}"]
        )
        for number, (hits, checksum) in sorted(data["lines"].items()):
            suffix = "" if checksum is None else f",{checksum}"
            output.append(f"DA:{number},{hits}{suffix}")
        output.extend([f"LF:{len(data['lines'])}", f"LH:{sum(hits > 0 for hits, _ in data['lines'].values())}"])
        for (number, block, branch), hits in sorted(data["branches"].items()):
            output.append(f"BRDA:{number},{block},{branch},{'-' if hits is None else hits}")
        output.extend(
            [
                f"BRF:{len(data['branches'])}",
                f"BRH:{sum(hits is not None and hits > 0 for hits in data['branches'].values())}",
                "end_of_record",
            ]
        )
    return "\n".join(output) + "\n"
