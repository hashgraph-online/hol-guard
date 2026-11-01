"""Sample Python call events on one thread with separate elapsed/CPU clocks."""

from __future__ import annotations

import sys
import threading
import time

from scripts.cigar_context_profile import ROOT_LABELS, source_label


class ThreadProfile:
    def __init__(self):
        self.samples = self.completed = 0
        self.errors = set()
        self.records = {}
        self._stack = []
        self._active = self._finished = False
        self._owner = None
        self._root = None
        self._hook = self._dispatch

    def call(self, function, *args, **kwargs):
        self.samples += 1
        previous = sys.getprofile()
        if previous is not None:
            self.errors.add("existing_profile_hook")
            return function(*args, **kwargs)
        self._owner = threading.get_ident()
        self._root = function.__code__
        self._stack = []
        self._active = self._finished = False
        sys.setprofile(self._hook)
        try:
            return function(*args, **kwargs)
        finally:
            still_owned = sys.getprofile() is self._hook
            sys.setprofile(previous)
            if not still_owned:
                self.errors.add("profile_hook_replaced")
            if self._stack or not self._finished:
                self.errors.add("sample_incomplete")
            else:
                self.completed += 1

    def _dispatch(self, frame, event, _arg):
        # No frame/locals/arguments are retained. The code object's fixed
        # source identity and numeric clock values suffice for stack matching.
        if threading.get_ident() != self._owner:
            self.errors.add("foreign_thread_event")
            return
        if event not in {"call", "return"} or self.errors:
            return
        code = frame.f_code
        if not self._active:
            if self._finished or event != "call" or code is not self._root:
                return
            self._active = True
        elapsed, cpu = time.monotonic_ns(), time.thread_time_ns()
        if event == "call":
            self._stack.append([code, elapsed, cpu, 0, 0])
            return
        if not self._stack or self._stack[-1][0] is not code:
            self.errors.add("unbalanced_call_events")
            return
        _code, started, cpu_started, child_elapsed, child_cpu = self._stack.pop()
        total_elapsed, total_cpu = elapsed - started, cpu - cpu_started
        own_elapsed, own_cpu = total_elapsed - child_elapsed, total_cpu - child_cpu
        if min(total_elapsed, total_cpu, own_elapsed, own_cpu) < 0:
            self.errors.add("negative_clock_accounting")
            return
        key = (code.co_filename, code.co_firstlineno, code.co_name)
        value = self.records.setdefault(key, [0, 0, 0, 0, 0])
        for index, amount in enumerate((1, own_elapsed, total_elapsed, own_cpu, total_cpu)):
            value[index] += amount
        if self._stack:
            self._stack[-1][3] += total_elapsed
            self._stack[-1][4] += total_cpu
        else:
            self._active = False
            self._finished = True

    def summary(self, roots, *, limit=80):
        if set(roots) - ROOT_LABELS or not 1 <= limit <= 200:
            raise ValueError("thread profile reporting contract changed")
        values = []
        unmapped = 0
        unmapped_cpu = 0
        for key, (calls, own_elapsed, total_elapsed, own_cpu, total_cpu) in self.records.items():
            label = source_label(key, roots)
            if label is None:
                unmapped += 1
                unmapped_cpu += own_cpu
                continue
            values.append(
                {
                    **label,
                    "call_events": calls,
                    "self_elapsed_seconds": own_elapsed / 1e9,
                    "total_elapsed_seconds": total_elapsed / 1e9,
                    "self_cpu_seconds": own_cpu / 1e9,
                    "total_cpu_seconds": total_cpu / 1e9,
                }
            )
        values.sort(key=lambda value: (-value["self_cpu_seconds"], value["root"], value["module"], value["function"]))
        return {
            "sampled_compiles": self.samples,
            "completed_samples": self.completed,
            "profile_complete": self.samples > 0 and self.samples == self.completed and not self.errors,
            "errors": sorted(self.errors),
            "unmapped_functions": unmapped,
            "unmapped_self_cpu_seconds": unmapped_cpu / 1e9,
            "top_by_self_cpu": values[:limit],
        }
