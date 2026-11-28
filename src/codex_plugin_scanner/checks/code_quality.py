"""Code quality checks (10 points)."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CheckResult, Finding, Severity
from ..path_support import resolves_within_root

CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
EXCLUDED_DIRS = {"node_modules", ".git", "dist", ".next", "coverage", "__pycache__", ".venv", "venv"}

# A direct eval call is dangerous.  The prior word-boundary matcher also
# classified Puppeteer's $eval/$$eval and arbitrary member calls (client.eval)
# as dynamic execution, although none invokes the global eval function.
DIRECT_EVAL_RE = re.compile(r"(?<![\w$.#])eval\s*(?:\?\.)?\s*\(")
EXPLICIT_GLOBAL_EVAL_RE = re.compile(
    r"(?<![\w$.#])(?:globalThis|window|global|builtins|__builtins__)"
    r"\s*(?:\?\.|\.)\s*eval\s*(?:\?\.)?\s*\("
)
FUNCTION_RE = re.compile(r"new\s+Function\s*\(")
DECLARATION_SUFFIX_RE = re.compile(
    r"[ \t]*(?:/\*[^\r\n]*\*/[ \t]*)?"
    r"(?:\{|:[ \t]*(?:[^={;\r\n]|=>)+[ \t]*(?:\{|;))"
)
SINGLE_LINE_DECLARATION_RE = re.compile(
    r"eval\s*\(.*\)[ \t]*(?:/\*[^\r\n]*\*/[ \t]*)?"
    r"(?:\{|:[ \t]*(?:[^={;\r\n]|=>)+[ \t]*(?:\{|;))"
)
INTERPOLATED_TEMPLATE_PATTERN = r"`[^`]*\$\{[^}]+\}[^`]*`"
TS_TEMPLATE_SUFFIX_PATTERN = r"(?:[ \t]+(?:as|satisfies)[ \t]+[^;\n]+)?"
SHELL_CALL_PATTERN = r"(?:execSync|spawnSync|exec|spawn)"
SHELL_RECEIVER_PATTERN = (
    r"(?<![\w$])(?:child_process|childProcess|cp|"
    r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\))"
)
DIRECT_SHELL_TEMPLATE_RE = re.compile(
    rf"(?<![\w.]){SHELL_CALL_PATTERN}\s*\(\s*{INTERPOLATED_TEMPLATE_PATTERN}",
    re.S,
)
MEMBER_SHELL_TEMPLATE_RE = re.compile(
    rf"{SHELL_RECEIVER_PATTERN}\s*\.\s*{SHELL_CALL_PATTERN}\s*\(\s*{INTERPOLATED_TEMPLATE_PATTERN}",
    re.S,
)
INTERPOLATED_TEMPLATE_ASSIGNMENT_RE = re.compile(
    rf"\b(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)"
    rf"(?:\s*:\s*[^=;\n]+)?\s*=\s*{INTERPOLATED_TEMPLATE_PATTERN}"
    rf"{TS_TEMPLATE_SUFFIX_PATTERN}[ \t]*;?",
    re.S,
)


DIRECT_SHELL_CONCAT_RE = re.compile(
    rf"""(?<![\w.]){SHELL_CALL_PATTERN}\s*\(\s*"""
    r"""(?:(?:["'][^"']*["'][ \t]*\+[ \t]*[A-Za-z_$][\w$]*)|(?:[A-Za-z_$][\w$]*[ \t]*\+[ \t]*["']))""",
    re.S,
)
MEMBER_SHELL_CONCAT_RE = re.compile(
    rf"""{SHELL_RECEIVER_PATTERN}\s*\.\s*{SHELL_CALL_PATTERN}\s*\(\s*"""
    r"""(?:(?:["'][^"']*["'][ \t]*\+[ \t]*[A-Za-z_$][\w$]*)|(?:[A-Za-z_$][\w$]*[ \t]*\+[ \t]*["']))""",
    re.S,
)
CONCAT_ASSIGNMENT_RE = re.compile(
    r"""\b(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)"""
    r"""(?:\s*:\s*[^=;\n]+)?\s*=\s*"""
    r"""(?:(?:["'][^"']*["'][ \t]*\+[ \t]*[A-Za-z_$][\w$]*)|(?:[A-Za-z_$][\w$]*[ \t]*\+[ \t]*["']))[ \t]*;?""",
    re.S,
)


def _mask_code_literals_and_comments(
    content: str, *, is_python: bool = False, preserve_template_literals: bool = False
) -> str:
    """Mask string literals and comments with spaces, preserving length and newlines.

    Prevents false-positive matches in comments, string literals, regexes, and docstrings (#3531).
    """
    chars = list(content)
    length = len(chars)
    i = 0

    while i < length:
        if is_python and chars[i] == "#":
            while i < length and chars[i] != "\n":
                chars[i] = " "
                i += 1
            continue

        if not is_python and i + 1 < length and chars[i] == "/" and chars[i + 1] == "/":
            while i < length and chars[i] != "\n":
                chars[i] = " "
                i += 1
            continue

        if not is_python and i + 1 < length and chars[i] == "/" and chars[i + 1] == "*":
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            while i < length:
                if i + 1 < length and chars[i] == "*" and chars[i + 1] == "/":
                    chars[i] = " "
                    chars[i + 1] = " "
                    i += 2
                    break
                if chars[i] != "\n" and chars[i] != "\r":
                    chars[i] = " "
                i += 1
            continue

        if (
            is_python
            and (i + 2 < length)
            and (
                (chars[i] == '"' and chars[i + 1] == '"' and chars[i + 2] == '"')
                or (chars[i] == "'" and chars[i + 1] == "'" and chars[i + 2] == "'")
            )
        ):
            delim = chars[i]
            i += 3
            while i < length:
                if i + 2 < length and chars[i] == delim and chars[i + 1] == delim and chars[i + 2] == delim:
                    i += 3
                    break
                if chars[i] != "\n" and chars[i] != "\r":
                    chars[i] = " "
                i += 1
            continue

        if chars[i] in ('"', "'"):
            if preserve_template_literals:
                prev_idx = i - 1
                while prev_idx >= 0 and chars[prev_idx] in " \t\r\n":
                    prev_idx -= 1
                if prev_idx >= 0 and chars[prev_idx] == "(":
                    p2 = prev_idx - 1
                    while p2 >= 0 and chars[p2] in " \t\r\n":
                        p2 -= 1
                    call_end = p2 + 1
                    while p2 >= 0 and (chars[p2].isalnum() or chars[p2] in "_$"):
                        p2 -= 1
                    call_name = "".join(chars[p2 + 1 : call_end])
                    if call_name in ("require", "import"):
                        delim = chars[i]
                        i += 1
                        while i < length:
                            if chars[i] == delim:
                                i += 1
                                break
                            i += 1
                        continue

            delim = chars[i]
            i += 1
            escaped = False
            while i < length:
                c = chars[i]
                if escaped:
                    chars[i] = " "
                    escaped = False
                    i += 1
                    continue
                if c == "\\":
                    chars[i] = " "
                    escaped = True
                    i += 1
                    continue
                if c == delim:
                    i += 1
                    break
                if c != "\n" and c != "\r":
                    chars[i] = " "
                i += 1
            continue

        if not is_python and chars[i] == "`":
            if preserve_template_literals:
                i += 1
                continue
            i += 1
            escaped = False
            while i < length:
                c = chars[i]
                if escaped:
                    chars[i] = " "
                    escaped = False
                    i += 1
                    continue
                if c == "\\":
                    chars[i] = " "
                    escaped = True
                    i += 1
                    continue
                if c == "`":
                    i += 1
                    break
                if c == "$" and i + 1 < length and chars[i + 1] == "{":
                    i += 2
                    brace_depth = 1
                    while i < length and brace_depth > 0:
                        if chars[i] == "{":
                            brace_depth += 1
                        elif chars[i] == "}":
                            brace_depth -= 1
                        i += 1
                    continue
                if c != "\n" and c != "\r":
                    chars[i] = " "
                i += 1
            continue

        if not is_python and chars[i] == "/":
            prev_idx = i - 1
            while prev_idx >= 0 and chars[prev_idx] in " \t\r\n":
                prev_idx -= 1
            if prev_idx < 0 or chars[prev_idx] in "=([,:!&|?;~^{}":
                chars[i] = " "
                i += 1
                in_char_class = False
                escaped = False
                while i < length:
                    c = chars[i]
                    if escaped:
                        chars[i] = " "
                        escaped = False
                        i += 1
                        continue
                    if c == "\\":
                        chars[i] = " "
                        escaped = True
                        i += 1
                        continue
                    if c == "[":
                        in_char_class = True
                    elif c == "]":
                        in_char_class = False
                    elif c == "/" and not in_char_class:
                        chars[i] = " "
                        i += 1
                        while i < length and chars[i].isalpha():
                            chars[i] = " "
                            i += 1
                        break
                    if c != "\n" and c != "\r":
                        chars[i] = " "
                    i += 1
                continue

        i += 1

    return "".join(chars)


def _find_code_files(plugin_dir: Path, files: tuple[Path, ...] | None = None) -> list[Path]:
    if files is not None:
        return [
            path
            for path in files
            if path.is_file()
            and not path.is_symlink()
            and path.suffix in CODE_EXTS
            and resolves_within_root(plugin_dir, path, require_exists=True)
        ]
    discovered: list[Path] = []
    for p in plugin_dir.rglob("*"):
        if not p.is_file() or p.suffix not in CODE_EXTS:
            continue
        if any(part in EXCLUDED_DIRS for part in p.parts):
            continue
        if not resolves_within_root(plugin_dir, p, require_exists=True):
            continue
        discovered.append(p)
    return discovered


def _shell_call_uses_variable(content: str, variable: str) -> bool:
    escaped_variable = re.escape(variable)
    variable_boundary = r"(?![\w$])"
    direct_call = re.compile(rf"(?<![\w.]){SHELL_CALL_PATTERN}\s*\(\s*{escaped_variable}{variable_boundary}")
    member_call = re.compile(
        rf"{SHELL_RECEIVER_PATTERN}\s*\.\s*{SHELL_CALL_PATTERN}\s*\(\s*"
        rf"{escaped_variable}{variable_boundary}"
    )
    return bool(direct_call.search(content) or member_call.search(content))


def _has_shell_injection_pattern(content: str) -> bool:
    if (
        DIRECT_SHELL_TEMPLATE_RE.search(content)
        or MEMBER_SHELL_TEMPLATE_RE.search(content)
        or DIRECT_SHELL_CONCAT_RE.search(content)
        or MEMBER_SHELL_CONCAT_RE.search(content)
    ):
        return True

    for assignment in INTERPOLATED_TEMPLATE_ASSIGNMENT_RE.finditer(content):
        if _shell_call_uses_variable(content[assignment.end() :], assignment.group("name")):
            return True
    for assignment in CONCAT_ASSIGNMENT_RE.finditer(content):
        if _shell_call_uses_variable(content[assignment.end() :], assignment.group("name")):
            return True
    return False


def _matching_paren(content: str, opening_paren: int) -> int | None:
    """Find the matching parenthesis without treating quoted strings as syntax."""
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening_paren, len(content)):
        character = content[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _is_eval_declaration(content: str, match: re.Match[str]) -> bool:
    """Do not classify a method/function declaration named eval as a call."""
    closing_paren = _matching_paren(content, match.end() - 1)
    if closing_paren is None:
        return False

    # A declaration body or TypeScript signature must start on the same line as
    # the closing parameter delimiter.  Consuming a newline here would mistake
    # a valid direct call followed by a standalone block for a method body.
    if DECLARATION_SUFFIX_RE.match(content, closing_paren + 1):
        return True

    # The balanced-parenthesis helper intentionally remains lightweight and
    # does not parse regular-expression literals.  A same-line declaration
    # fallback still recognizes e.g. `eval(value = /)/) {}` without allowing a
    # following-line block to suppress a direct call.
    line_end = content.find("\n", match.start())
    if line_end == -1:
        line_end = len(content)
    if SINGLE_LINE_DECLARATION_RE.match(content, match.start(), line_end):
        return True

    line_start = content.rfind("\n", 0, match.start()) + 1
    prefix = content[line_start : match.start()].strip()
    return bool(re.search(r"(?:^|\s)def$", prefix))


def _is_member_access_eval(content: str, match: re.Match[str]) -> bool:
    """Return whether eval is preceded by member-access punctuation."""
    index = match.start()
    while index:
        if content[index - 1].isspace():
            index -= 1
            continue
        if index >= 2 and content[index - 2 : index] == "*/":
            comment_start = content.rfind("/*", 0, index - 2)
            if comment_start == -1:
                break
            index = comment_start
            continue
        line_start = max(content.rfind("\n", 0, index), content.rfind("\r", 0, index)) + 1
        comment_start = content.rfind("//", line_start, index)
        if comment_start != -1:
            index = comment_start
            continue
        break
    return index > 0 and content[index - 1] == "."


def _has_direct_eval_call(content: str) -> bool:
    for match in DIRECT_EVAL_RE.finditer(content):
        if _is_member_access_eval(content, match):
            continue
        if not _is_eval_declaration(content, match):
            return True
    return bool(EXPLICIT_GLOBAL_EVAL_RE.search(content))


def check_no_eval(plugin_dir: Path, files: tuple[Path, ...] | None = None) -> CheckResult:
    findings: list[str] = []
    for fpath in _find_code_files(plugin_dir, files):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        masked = _mask_code_literals_and_comments(content, is_python=(fpath.suffix == ".py"))
        if _has_direct_eval_call(masked):
            findings.append(f"{fpath.relative_to(plugin_dir)}: eval()")
        if FUNCTION_RE.search(masked):
            findings.append(f"{fpath.relative_to(plugin_dir)}: new Function()")
    if not findings:
        return CheckResult(
            name="No eval or Function constructor",
            passed=True,
            points=5,
            max_points=5,
            message="No eval() or new Function() usage detected",
        )
    return CheckResult(
        name="No eval or Function constructor",
        passed=False,
        points=0,
        max_points=5,
        message=f"Found: {', '.join(findings[:3])}",
        findings=tuple(
            Finding(
                rule_id="DANGEROUS_DYNAMIC_EXECUTION",
                severity=Severity.HIGH,
                category="code-quality",
                title="Dynamic code execution detected",
                description=f"{entry} uses eval() or new Function().",
                remediation="Remove dynamic code evaluation and replace it with explicit control flow.",
                file_path=entry.split(":")[0],
            )
            for entry in findings
        ),
    )


def check_no_shell_injection(plugin_dir: Path, files: tuple[Path, ...] | None = None) -> CheckResult:
    findings: list[str] = []
    for fpath in _find_code_files(plugin_dir, files):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        masked = _mask_code_literals_and_comments(
            content, is_python=(fpath.suffix == ".py"), preserve_template_literals=True
        )
        if _has_shell_injection_pattern(masked):
            findings.append(str(fpath.relative_to(plugin_dir)))
    if not findings:
        return CheckResult(
            name="No shell injection patterns",
            passed=True,
            points=5,
            max_points=5,
            message="No shell injection patterns detected",
        )
    return CheckResult(
        name="No shell injection patterns",
        passed=False,
        points=0,
        max_points=5,
        message=f"Shell injection patterns in: {', '.join(findings)}",
        findings=tuple(
            Finding(
                rule_id="SHELL_INJECTION_PATTERN",
                severity=Severity.HIGH,
                category="code-quality",
                title="Potential shell injection pattern detected",
                description=f"{path} interpolates untrusted values into a shell execution call.",
                remediation="Pass arguments as structured arrays and validate user-controlled input before execution.",
                file_path=path,
            )
            for path in findings
        ),
    )


def run_code_quality_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_no_eval(plugin_dir),
        check_no_shell_injection(plugin_dir),
    )
