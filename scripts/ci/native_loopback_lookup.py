"""Bounded macOS lookup witnesses, after qualification and before DNS cleanup.

Every lookup is fixed to loopback. Only a child created here can be sampled.
No original benchmark process is inspected or changed, and raw native stacks
are never exported. Diagnostic timings are not qualification samples.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

REVERSE_NAME = "1.0.0.127.in-addr.arpa"


class _Responder(Protocol):
    @property
    def port(self) -> int: ...

    def snapshot(self) -> dict[str, int]: ...


LOOKUP_SECONDS = 5.0
_SYSTEM_OUTPUT_BYTES = 128 * 1024
_HOSTS_DIRECTORY = Path("/private/etc")
_LOOKUPS = {
    "numeric_control": "socket.getnameinfo(('127.0.0.1', 0), socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)[0]",
    "gethostbyaddr": "socket.gethostbyaddr('127.0.0.1')[0]",
    "getnameinfo": "socket.getnameinfo(('127.0.0.1', 0), socket.NI_NAMEREQD | socket.NI_NUMERICSERV)[0]",
}
_STACK_CATEGORIES = {
    "python_lookup": frozenset({"socket_gethostbyaddr", "socket_getnameinfo", "setipaddr"}),
    "libinfo_search": frozenset({"gethostbyaddr", "si_host_byaddr", "search_host_byaddr", "si_search", "getnameinfo"}),
    "directory_lookup": frozenset({"ds_host_byaddr", "ds_hostbyaddr", "ds_query", "si_muser_call"}),
    "mdns_query": frozenset({"mdns_hostbyaddr", "_mdns_search", "_mdns_search_ex", "_mdns_query_start"}),
    "mdns_ipc": frozenset({"DNSServiceQueryRecord", "DNSServiceQueryRecordWithAttribute", "DNSServiceProcessResult"}),
    "kevent_wait": frozenset({"kevent", "kevent64", "kevent_qos"}),
    "pthread_wait": frozenset({"pthread_mutex_lock", "__psynch_mutexwait", "__psynch_cvwait"}),
    "mach_wait": frozenset({"mach_msg", "mach_msg2_trap", "mach_msg_trap", "_dispatch_mach_send_and_wait_for_reply"}),
    "socket_wait": frozenset({"recv", "recvfrom", "recvmsg", "read", "poll", "select"}),
}


def stack_summary(data: bytes) -> dict[str, Any]:
    """Recognize only function frames in sample's call graph, never headers."""
    text = data.decode("utf-8", errors="replace")
    body = text.partition("Call graph:")[2].partition("Total number in stack")[0]
    categories: set[str] = set()
    count = 0
    for line in body.splitlines():
        match = re.match(r"^\s*(?:[+!:|]\s*)*\d+\s+([A-Za-z_][A-Za-z0-9_.$]{0,127})\s*(?:\(|\+|$)", line)
        if match is None:
            continue
        function = match.group(1)
        recognized = {name for name, functions in _STACK_CATEGORIES.items() if function in functions}
        if recognized:
            count += 1
            categories.update(recognized)
    return {
        "categories": sorted(categories),
        "recognized_frames": count,
        "stack_sha256": hashlib.sha256(data).hexdigest(),
        "stack_bytes": len(data),
    }


def _bounded_process(
    arguments: list[str],
    *,
    timeout: float,
    limit: int,
    sample_owned: bool = False,
    output_observer: Callable[[bytes, bytes], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], bytes]:
    started = time.monotonic()
    deadline = started + timeout
    report: dict[str, Any] = {
        "status": "completed",
        "contained": False,
        "terminal_observation": "not_observed",
        "terminal_observation_pid_matches": None,
        "terminal_si_code": None,
        "terminal_si_status": None,
        "terminal_wait_errno": None,
        "group_retirement_errno": None,
    }
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    process = None
    sample_attempted = False
    try:
        process = subprocess.Popen(
            arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
        )
        with selectors.DefaultSelector() as selector:
            for channel in buffers:
                stream = getattr(process, channel)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, channel)
            while selector.get_map():
                now = time.monotonic()
                if now >= deadline:
                    report["status"] = "deadline_exceeded"
                    break
                if sample_owned and not sample_attempted and now - started >= 0.25:
                    # The child remains unreaped while sample runs, preventing
                    # PID reuse. No caller-supplied PID or process is accepted.
                    sample_attempted = True
                    sample, trace = _bounded_process(
                        ["/usr/bin/sample", str(process.pid), "1", "10", "-mayDie", "-file", "/dev/stdout"],
                        timeout=min(2.0, deadline - now),
                        limit=64 * 1024,
                    )
                    report["native_sample"] = {**sample, **stack_summary(trace)}
                    continue
                for key, _mask in selector.select(min(0.05, deadline - now)):
                    remaining = limit - sum(len(value) for value in buffers.values())
                    chunk = os.read(key.fd, min(8192, remaining + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(chunk) > remaining:
                        buffers[key.data].extend(chunk[:remaining])
                        report["status"] = "size_limit"
                        break
                    else:
                        buffers[key.data].extend(chunk)
                if report["status"] != "completed":
                    break
        if report["status"] == "completed":
            # Observe termination without reaping: the leader PID continues to
            # reserve ownership of its process group until group retirement.
            if not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
                report["status"] = "terminal_observation_unavailable"
            else:
                while time.monotonic() < deadline:
                    try:
                        terminal = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    except OSError as error:
                        report["terminal_wait_errno"] = error.errno
                        raise
                    if terminal is not None:
                        report["terminal_observation"] = "observed"
                        report["terminal_observation_pid_matches"] = terminal.si_pid == process.pid
                        report["terminal_si_code"] = terminal.si_code
                        report["terminal_si_status"] = terminal.si_status
                        break
                    time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
                else:
                    report["status"] = "deadline_exceeded"
            if time.monotonic() >= deadline:
                report["status"] = "deadline_exceeded"
    except OSError as error:
        report.update(status="unavailable", errno=error.errno)
    finally:
        if process is not None:
            retired = False
            try:
                # Retire even when the leader exited: descendants can retain
                # pipes, or close them and outlive a successful leader.
                os.killpg(process.pid, signal.SIGKILL)
                report["group_retirement"] = "signalled"
                retired = True
            except ProcessLookupError as error:
                report["group_retirement"] = "absent"
                report["group_retirement_errno"] = error.errno
                retired = True
            except OSError as error:
                report["group_retirement"] = "failed"
                report["group_retirement_errno"] = error.errno
                report["status"] = "containment_failed"
            try:
                process.wait(timeout=1)
                report["leader_reaped"] = True
                report["contained"] = retired
            except subprocess.TimeoutExpired:
                report["status"] = "containment_failed"
            report["return_code"] = process.returncode
            for channel in buffers:
                stream = getattr(process, channel)
                if stream is not None:
                    stream.close()
    report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    for channel, data in buffers.items():
        report[channel + "_bytes"] = len(data)
        report[channel + "_sha256"] = hashlib.sha256(data).hexdigest()
    if output_observer is not None:
        report["observation"] = output_observer(bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    return report, bytes(buffers["stdout"])


def lookup_probe(operation: str, responder: _Responder) -> dict[str, Any]:
    expression = _LOOKUPS[operation]
    code = (
        "import json,socket\ntry:\n name=" + expression + "\n print(json.dumps({'status':'completed',"
        "'loopback_label':name in ('127.0.0.1','localhost','hol-guard-qualification.localhost')}),flush=True)\n"
        "except Exception as error:\n print(json.dumps({'status':'lookup_error','category':type(error).__name__,"
        "'errno':getattr(error,'errno',None)}),flush=True)\n"
    )
    before = responder.snapshot()["received"]
    report, data = _bounded_process(
        [sys.executable, "-I", "-c", code],
        timeout=LOOKUP_SECONDS,
        limit=1024,
        sample_owned=operation != "numeric_control",
    )
    report["operation"] = operation
    report["responder_packet_delta"] = max(0, responder.snapshot()["received"] - before)
    if report["status"] == "completed" and report.get("return_code") == 0:
        report["lookup"] = {"status": "invalid_child_evidence"}
        try:
            value = json.loads(data)
            if value.get("status") == "completed" and type(value.get("loopback_label")) is bool:
                report["lookup"] = {"status": "completed", "loopback_label": value["loopback_label"]}
            elif value.get("status") == "lookup_error":
                kind = value.get("category")
                report["lookup"] = {"status": "lookup_error"}
                if isinstance(kind, str) and re.fullmatch(r"[A-Za-z]{1,64}", kind):
                    report["lookup"]["category"] = kind
                if type(value.get("errno")) is int:
                    report["lookup"]["errno"] = value["errno"]
        except (ValueError, TypeError, AttributeError):
            report["lookup"] = {"status": "invalid_child_evidence"}
    return report


def dns_service_summary(stdout: bytes, stderr: bytes) -> dict[str, Any]:
    """Project actual dns-sd callback rows; process exit is a separate witness."""
    text = stdout.decode("utf-8", errors="replace")
    errors = stderr.decode("utf-8", errors="replace")
    counts = dict(callbacks=0, positive=0, negative=0, removed=0, unclassified=0, loopback_label=0)
    unparsed = dict(rows=0, negative_interface_prefix=0, ptr_in_columns=0, negative_answer_suffix=0)
    callback_flags: set[int] = set()
    # The optional single character is dns-sd's DNSSEC display column. Match
    # only this fixed query/type/class, never arbitrary diagnostic text.
    row = re.compile(
        r"^\s*\d{1,2}:\d{2}:\d{2}\.\d{3}\s+(Add|Rmv)\s+([0-9A-Fa-f]{1,8})\s+"
        r"(?:\S\s+)?\d{1,10}\s+" + re.escape(REVERSE_NAME) + r"\.?\s+PTR\s+IN\s+(.+?)\s*$"
    )
    for line in text.splitlines():
        match = row.fullmatch(line)
        if match is None:
            # Retain only counts for the fixed query. Unknown row layouts do
            # not become positive/negative callbacks or successful lookups.
            fixed_name = re.escape(REVERSE_NAME) + r"\.?"
            if re.match(r"^\s*\d{1,2}:\d{2}:\d{2}\.\d{3}\s", line) and re.search(
                r"(?<!\S)" + fixed_name + r"(?=\s)", line
            ):
                unparsed["rows"] += 1
                unparsed["negative_interface_prefix"] += bool(re.search(r"\s-\d{1,10}\s+" + fixed_name, line))
                unparsed["ptr_in_columns"] += bool(re.search(fixed_name + r"\s+PTR\s+IN\s", line))
                unparsed["negative_answer_suffix"] += line.endswith(("    No Such Record", "    No Authorization"))
            continue
        operation, raw_flags, answer = match.groups()
        flags = int(raw_flags, 16)
        counts["callbacks"] += 1
        if len(callback_flags) < 16:
            callback_flags.add(flags)
        if answer.endswith(("    No Such Record", "    No Authorization")):
            counts["negative"] += 1
        elif operation == "Rmv":
            counts["removed"] += 1
        elif flags & 2 and re.fullmatch(r"(?:[A-Za-z0-9_-]{1,63}\.){1,127}", answer):
            counts["positive"] += 1
            counts["loopback_label"] += int(answer.lower() in ("localhost.", "hol-guard-qualification.localhost."))
        else:
            counts["unclassified"] += 1
    api_errors = sorted(
        {
            int(value)
            for value in re.findall(
                r"(?m)^(?:DNSServiceQueryRecord failed|Error code) (-?\d{1,10})(?: \(Service Not Running\))?\s*$",
                text + "\n" + errors,
            )
            if -(2**31) <= int(value) < 2**31
        }
    )[:16]
    unsupported = " -Q <name> <rrtype> <rrclass>" in errors or bool(
        re.search(r"(?im)^(?:.*dns-sd: )?(?:illegal|invalid|unknown) option\b", errors)
    )
    return {
        "api": "DNSServiceQueryRecord",
        "callback_observation": "rows_captured" if counts["callbacks"] else "none_in_captured_output",
        "counts": counts,
        "unparsed_fixed_question_rows": unparsed,
        "callback_flags": sorted(callback_flags),
        "api_errors": api_errors,
        "unsupported_syntax_observed": unsupported,
        "stdout_format_recognized": bool(counts["callbacks"] or "...STARTING..." in text or api_errors),
    }


def dns_service_probe(responder: _Responder) -> dict[str, Any]:
    before = responder.snapshot()["received"]
    report, _data = _bounded_process(
        ["/usr/bin/dns-sd", "-m", "-Q", REVERSE_NAME, "PTR", "IN"],
        timeout=LOOKUP_SECONDS,
        limit=_SYSTEM_OUTPUT_BYTES,
        output_observer=dns_service_summary,
    )
    report["operation"] = "dns_service_reverse_ptr"
    report["exit_after_available_batch_requested"] = True
    report["force_multicast_option_used"] = False
    report["libc_equivalence_claimed"] = False
    report["responder_packet_delta"] = max(0, responder.snapshot()["received"] - before)
    # A callback and an outer timeout can both be true. Never replace the
    # process status with a parsed answer or infer no callback from timeout.
    return report


def matched_resolver_summary(stdout: bytes, _stderr: bytes, port: int) -> dict[str, Any]:
    text = stdout.decode("utf-8", errors="replace")
    matches: list[dict[str, object]] = []
    matched_count = 0
    allowed = {"Supplemental", "Scoped", "ServiceSpecific", "Request A records", "Request AAAA records"}
    for block in re.split(r"(?m)^resolver #\d+\s*$", text)[1:]:
        if re.findall(r"(?m)^\s*domain\s*:\s*(\S+)\s*$", block) != [REVERSE_NAME]:
            continue
        if re.findall(r"(?m)^\s*nameserver\[\d+\]\s*:\s*(\S+)\s*$", block) != ["127.0.0.1"]:
            continue
        if re.findall(r"(?m)^\s*port\s*:\s*(\d+)\s*$", block) != [str(port)]:
            continue
        matched_count += 1
        if len(matches) >= 8:
            continue
        reach = re.findall(r"(?m)^\s*reach\s*:\s*0x([0-9A-Fa-f]{1,8})(?:\s+\([^\n]*\))?\s*$", block)
        raw_flags = re.findall(r"(?m)^\s*flags\s*:\s*([^\n]*)$", block)
        flags = [item.strip() for value in raw_flags for item in value.split(",") if item.strip()]
        matches.append(
            {
                "reachability_value": int(reach[0], 16) if len(reach) == 1 else None,
                "reachability_field_count": len(reach),
                "flags": sorted({flag for flag in flags if flag in allowed}),
                "unknown_flag_count": sum(flag not in allowed for flag in flags),
            }
        )
    return {
        "exact_configuration_match_count": matched_count,
        "matched_blocks": matches,
        "matched_blocks_truncated": matched_count > len(matches),
        "actual_query_routing_proven": False,
    }


def hosts_mapping_summary(content: bytes) -> dict[str, Any]:
    """Count only exact canonical labels, not substring or comment matches."""
    counts = dict(
        ipv4_records=0, ipv6_records=0, ipv4_localhost=0, ipv6_localhost=0, localhost_conflicts=0, malformed=0
    )
    for raw_line in content.splitlines():
        line = raw_line.partition(b"#")[0].strip()
        if not line:
            continue
        try:
            fields = line.decode("ascii", errors="strict").split()
        except UnicodeError:
            counts["malformed"] += 1
            continue
        if len(fields) < 2 or any(ord(character) < 32 for character in "".join(fields)):
            counts["malformed"] += 1
            continue
        address, *names = fields
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            counts["malformed"] += 1
            continue
        # Do not resolve or normalize other addresses. Canonical loopback
        # spelling and the exact localhost token are the only presence claim.
        local = "localhost" in names
        if address == "127.0.0.1":
            counts["ipv4_records"] += 1
            counts["ipv4_localhost"] += int(local)
        elif address == "::1":
            counts["ipv6_records"] += 1
            counts["ipv6_localhost"] += int(local)
        elif local and str(parsed_address) not in {"127.0.0.1", "::1"}:
            counts["localhost_conflicts"] += 1
    return {
        **counts,
        "exact_ipv4_localhost_present": counts["ipv4_localhost"] > 0,
        "exact_ipv6_localhost_present": counts["ipv6_localhost"] > 0,
        "duplicate_ipv4_localhost_records": max(0, counts["ipv4_localhost"] - 1),
        "duplicate_ipv6_localhost_records": max(0, counts["ipv6_localhost"] - 1),
    }


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
    )


def hosts_mapping_witness() -> dict[str, Any]:
    directory_fd = descriptor = None
    try:
        directory_fd = os.open(_HOSTS_DIRECTORY, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
        directory = os.fstat(directory_fd)
        descriptor = os.open("hosts", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        report = {
            "status": "read",
            "root_owned": before.st_uid == 0,
            "mode": stat.S_IMODE(before.st_mode),
            "uid": before.st_uid,
            "gid": before.st_gid,
            "device": before.st_dev,
            "inode": before.st_ino,
            "links": before.st_nlink,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "expected_directory_trusted": directory.st_uid == 0 and not bool(directory.st_mode & 0o022),
            "file_trusted": before.st_uid == 0 and not bool(before.st_mode & 0o022) and before.st_nlink == 1,
        }
        if not stat.S_ISREG(before.st_mode):
            return {**report, "status": "not_regular"}
        content = bytearray()
        while len(content) <= _SYSTEM_OUTPUT_BYTES:
            chunk = os.read(descriptor, min(8192, _SYSTEM_OUTPUT_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat("hosts", dir_fd=directory_fd, follow_symlinks=False)
        named_directory = os.stat(_HOSTS_DIRECTORY, follow_symlinks=False)
        if (directory.st_dev, directory.st_ino) != (named_directory.st_dev, named_directory.st_ino):
            return {**report, "status": "changed_during_read"}
        if _file_identity(before) != _file_identity(after) or _file_identity(after) != _file_identity(named):
            return {**report, "status": "changed_during_read"}
        if len(content) > _SYSTEM_OUTPUT_BYTES:
            return {**report, "status": "size_limit"}
        if len(content) != after.st_size:
            return {**report, "status": "changed_during_read"}
        return {
            **report,
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "mapping": hosts_mapping_summary(bytes(content)),
        }
    except OSError as error:
        return {"status": "unavailable", "errno": error.errno}
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def lookup_witness(responder: _Responder) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.native-loopback-lookup-witness.v2",
        "phase": "after_qualification_before_resolver_cleanup",
        "qualification_outcomes_changed": False,
        "qualification_sample": False,
        "baseline_modified": False,
        "fixed_loopback_only": True,
        "packet_delta_scope": "responder_window_including_system_activity",
        "process_deadline_seconds": LOOKUP_SECONDS,
        "probes": [],
    }
    for operation in _LOOKUPS:
        report["probes"].append(lookup_probe(operation, responder))
    # Ordered after the original libc probes: these real system queries may
    # populate caches and cannot be treated as before/after performance arms.
    report["hosts_mapping"] = hosts_mapping_witness()
    if type(getattr(responder, "port", None)) is int:
        report["matched_resolver"], _data = _bounded_process(
            ["/usr/sbin/scutil", "--dns"],
            timeout=LOOKUP_SECONDS,
            limit=_SYSTEM_OUTPUT_BYTES,
            output_observer=lambda stdout, stderr: matched_resolver_summary(stdout, stderr, responder.port),
        )
    report["dns_service_reverse"] = dns_service_probe(responder)
    report["system_output_limit_bytes"] = _SYSTEM_OUTPUT_BYTES
    report["probe_order"] = [*_LOOKUPS, "hosts_mapping", "matched_resolver", "dns_service_reverse_ptr"]
    return report
