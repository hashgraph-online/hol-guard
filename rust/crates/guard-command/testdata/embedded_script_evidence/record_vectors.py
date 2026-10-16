"""Record embedded-script audit evidence from the Python owner before it retires.

Run from a source tree whose ``guard/runtime/embedded_script_evidence.py`` still
derived the entries in Python (heredoc extraction and command parsing went
through the native resident; owner matching, execution status, hashing and
truncation were Python). That module now delegates to the native
``embedded_script_evidence`` shell helper action, so this script documents how
``vectors.json`` was produced rather than re-running against the current tree.

The recording ran on POSIX. ``windows_style_path`` also carries hand-added
``windows_entries``: on Windows the owner's tokenizer keeps unquoted
backslashes literal, so the executable is ``python.exe``.

Usage (with a native runtime available)::

    python record_vectors.py vectors.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.embedded_script_evidence import embedded_script_evidence_entries

SCRIPT_OWNERS = ("ash", "bash", "bun", "dash", "deno", "node", "perl", "php", "python", "python3", "ruby", "sh", "zsh")


def _cases() -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = [
        ("empty", ""),
        ("whitespace", "   \n\t"),
        ("no_heredoc", "echo hello"),
        ("here_string", "cat <<< 'not a heredoc'"),
        ("arithmetic_shift", "echo $((1 << 2))"),
    ]
    cases += [(f"owner_{name}", f"{name} <<EOF\nprint('hi')\nEOF") for name in SCRIPT_OWNERS]
    cases += [
        ("owner_python_dash", "python - <<'PY'\nimport os\nprint(os.getcwd())\nPY"),
        ("owner_node_stdin", "node --input-type=module <<'JS'\nconsole.log(1)\nJS"),
        ("single_quoted_delimiter", "bash <<'EOF'\necho $HOME\nEOF"),
        ("double_quoted_delimiter", 'bash <<"EOF"\necho $HOME\nEOF'),
        ("partially_quoted_delimiter", "bash <<E'O'F\necho hi\nEOF"),
        ("backslash_delimiter", "bash <<\\EOF\necho hi\nEOF"),
        ("strip_tabs", "bash <<-EOF\n\techo hi\n\t\techo there\n\tEOF"),
        ("strip_tabs_quoted", "sh <<-'END'\n\tls -la\nEND"),
        ("space_before_delimiter", "bash << EOF\necho spaced\nEOF"),
        ("cat_to_file", "cat > script.sh <<EOF\n#!/bin/sh\necho hi\nEOF"),
        ("cat_append", "cat >> notes.txt <<'EOF'\nline one\nline two\nEOF"),
        ("tee_file", "tee config.yaml <<EOF\nkey: value\nEOF"),
        ("tee_sudo", "sudo tee /etc/hosts.d/x <<EOF\n127.0.0.1 x\nEOF"),
        ("kubectl_unknown", "kubectl apply -f - <<EOF\napiVersion: v1\nkind: ConfigMap\nEOF"),
        ("mysql_unknown", "mysql -u root <<SQL\nSELECT 1;\nSQL"),
        ("pipeline_cat_bash", "cat <<EOF | bash\necho piped\nEOF"),
        ("pipeline_cat_python", "cat <<'PY' | python3\nprint(1)\nPY"),
        ("and_chain_second", "cd /tmp && python3 <<EOF\nprint(2)\nEOF"),
        ("semicolon_chain", "echo start; bash <<EOF\necho two\nEOF"),
        ("two_heredocs_one_line", "cat <<A; bash <<B\nalpha\nA\necho beta\nB"),
        ("two_heredocs_lines", "cat > a.txt <<EOF\na\nEOF\npython3 <<EOF\nprint('b')\nEOF"),
        ("three_mixed", "tee a <<X\n1\nX\nnode <<Y\nconsole.log(2)\nY\nkubectl apply -f - <<Z\nk: v\nZ"),
        ("absolute_python", "/usr/bin/python3 <<EOF\nprint(1)\nEOF"),
        ("absolute_bash", "/bin/bash <<EOF\necho x\nEOF"),
        ("relative_path_owner", "./venv/bin/python <<EOF\nprint(1)\nEOF"),
        ("uppercase_owner", "BASH <<EOF\necho x\nEOF"),
        ("windows_style_path", "C:\\Python\\python.exe <<EOF\nprint(1)\nEOF"),
        ("python_exe_suffix", "python3.exe <<EOF\nprint(1)\nEOF"),
        ("python_version_suffix", "python3.12 <<EOF\nprint(1)\nEOF"),
        ("env_wrapper", "env python3 <<EOF\nprint(1)\nEOF"),
        ("env_assignment_wrapper", "env FOO=1 bash <<EOF\necho $FOO\nEOF"),
        ("usr_bin_env_wrapper", "/usr/bin/env node <<EOF\nconsole.log(1)\nEOF"),
        ("sudo_wrapper", "sudo bash <<EOF\nwhoami\nEOF"),
        ("sudo_user_wrapper", "sudo -u nobody sh <<EOF\nid\nEOF"),
        ("nohup_wrapper", "nohup bash <<EOF\necho bg\nEOF"),
        ("timeout_wrapper", "timeout 5 python3 <<EOF\nprint(1)\nEOF"),
        ("leading_assignment", "FOO=bar bash <<EOF\necho $FOO\nEOF"),
        ("bash_c_wrapper", "bash -c 'python3 <<EOF\nprint(1)\nEOF'"),
        ("subshell", "(bash <<EOF\necho sub\nEOF\n)"),
        ("command_substitution", 'out="$(python3 <<EOF\nprint(1)\nEOF\n)"'),
        ("non_ascii_body", "python3 <<EOF\nprint('héllo wörld ✓')\nEOF"),
        ("non_ascii_prefix", "echo 'héllo ✓ 日本' && bash <<EOF\necho ok\nEOF"),
        ("non_ascii_prefix_cat", "echo ünïcödé; cat > f.txt <<EOF\nü\nEOF"),
        ("emoji_prefix", "echo 🎉🎉 && python3 <<EOF\nprint('🎉')\nEOF"),
        ("emoji_delimiter_body", "bash <<EOF\n🎉\n日本語\nEOF"),
        ("non_ascii_wrapper_prefix", "FOO=ü env python3 <<EOF\nprint(1)\nEOF"),
        ("crlf", "bash <<EOF\r\necho crlf\r\nEOF\r\n"),
        ("crlf_body_only", "bash <<EOF\necho crlf\r\nEOF"),
        ("empty_body", "bash <<EOF\nEOF"),
        ("blank_line_body", "bash <<EOF\n\nEOF"),
        ("body_without_trailing_newline", "cat <<EOF\nno newline"),
        ("unterminated", "python3 <<EOF\nprint(1)\nprint(2)"),
        ("unterminated_no_body", "bash <<EOF"),
        ("unterminated_trailing_newline", "bash <<EOF\n"),
        ("unbalanced_quote_before", "echo 'unterminated && bash <<EOF\necho x\nEOF"),
        ("unbalanced_quote_body", "bash <<EOF\necho 'oops\nEOF"),
        ("unbalanced_double_quote_after", 'bash <<EOF\necho x\nEOF\necho "dangling'),
        ("heredoc_in_quotes", "echo '<<EOF'\nEOF"),
        ("heredoc_comment", "echo hi # <<EOF\nEOF"),
        ("delimiter_with_dash", "bash <<END-OF-SCRIPT\necho x\nEND-OF-SCRIPT"),
        ("delimiter_indented_not_closed", "bash <<EOF\necho x\n  EOF\nEOF"),
        ("body_contains_heredoc_text", "cat > gen.sh <<'OUTER'\nbash <<INNER\necho x\nINNER\nOUTER"),
        ("redirect_then_heredoc", "python3 >out.log 2>&1 <<EOF\nprint(1)\nEOF"),
        ("heredoc_before_args", "bash <<EOF -s arg\necho $1\nEOF"),
        ("multiline_body", "bash <<EOF\nline1\nline2\nline3\nEOF"),
        ("long_prefix_chain", "a && b && c && d && e; f | g | python3 <<EOF\nprint(1)\nEOF"),
        ("deno_run", "deno run - <<EOF\nconsole.log(1)\nEOF"),
        ("bun_run", "bun run - <<EOF\nconsole.log(1)\nEOF"),
        ("php_owner", "php <<'PHP'\n<?php echo 1;\nPHP"),
        ("perl_owner", "perl <<'PL'\nprint 1;\nPL"),
        ("ruby_owner", "ruby <<'RB'\nputs 1\nRB"),
        ("bare_heredoc", "<<EOF\nx\nEOF"),
        ("assignment_only", "FOO=1 <<EOF\nx\nEOF"),
        ("long_wrapper_shift", "sudo -u nobody nohup env A=1 B=2 bash <<EOF\necho\nEOF"),
        ("command_builtin_wrapper", "command sudo /usr/bin/env -i bash <<EOF\nx\nEOF"),
        ("segment_limit", "true; " * 140 + "bash <<EOF\necho x\nEOF"),
        ("byte_limit", "echo " + "a" * 33_000 + "; bash <<EOF\necho x\nEOF"),
    ]
    many = "\n".join(f"cat > f{i}.txt <<E{i}\nbody {i}\nE{i}" for i in range(8))
    cases.append(("exactly_eight", many))
    nine = many + "\npython3 <<E8\nprint(8)\nE8"
    cases.append(("nine_truncated", nine))
    twelve = "\n".join(f"{'bash' if i % 2 else 'tee x'} <<D{i}\necho {i}\nD{i}" for i in range(12))
    cases.append(("twelve_truncated", twelve))
    cases.append(
        (
            "ten_on_one_line",
            " ; ".join(f"cat <<H{i}" for i in range(10)) + "\n" + "\n".join(f"b{i}\nH{i}" for i in range(10)),
        )
    )
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    vectors = [
        {"name": name, "command": command, "entries": embedded_script_evidence_entries(command)}
        for name, command in _cases()
    ]
    names = [vector["name"] for vector in vectors]
    if len(names) != len(set(names)):
        raise SystemExit("duplicate vector names")
    args.output.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
