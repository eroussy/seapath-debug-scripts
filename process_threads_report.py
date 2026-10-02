#!/usr/bin/env python3
# Copyright (C) 2026 Savoir-faire Linux Inc.
# SPDX-License-Identifier: Apache-2.0
"""Report scheduler, affinity, and CPU data for every thread of a process."""

import argparse
import json
import os
import sys

from _process_threads import PROC, process_rows, read_text, print_process, use_color


def positive_pid(value):
    try:
        pid = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("PID must be a positive integer") from error
    if pid <= 0:
        raise argparse.ArgumentTypeError("PID must be a positive integer")
    return pid


def find_processes_by_name(name):
    matches = []
    try:
        process_entries = PROC.iterdir()
        for process in process_entries:
            if not process.name.isdecimal():
                continue
            pid = int(process.name)
            comm = read_text(process / "comm")
            cmdline = read_text(process / "cmdline") or ""
            executable = os.path.basename(cmdline.split("\0", 1)[0])
            if name == comm or name == executable:
                matches.append(pid)
    except PermissionError:
        return matches
    return matches


def main():
    parser = argparse.ArgumentParser(
        description="Show scheduler, affinity, and CPU data for a process's threads."
    )
    parser.add_argument(
        "name",
        nargs="?",
        help="exact process name, matching /proc comm or executable basename",
    )
    parser.add_argument("--pid", type=positive_pid, help="process ID")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="color human output (default: auto)",
    )
    args = parser.parse_args()

    if (args.pid is None) == (args.name is None):
        parser.error("provide either a process name or --pid")

    pid = args.pid
    if args.name is not None:
        matches = find_processes_by_name(args.name)
        if not matches:
            print(f"Process not found: {args.name}", file=sys.stderr)
            return 1
        if len(matches) > 1:
            pids = ", ".join(map(str, sorted(matches)))
            print(
                f"Process name matched multiple processes: {args.name} (PIDs: {pids}). "
                "Specify a PID.",
                file=sys.stderr,
            )
            return 1
        pid = matches[0]

    process_dir = PROC / str(pid)
    if not process_dir.is_dir():
        print(f"Process not found or inaccessible: {pid}", file=sys.stderr)
        return 1

    process_name = read_text(process_dir / "comm") or "?"
    rows = process_rows(pid)
    if not rows:
        print(f"No readable threads found for process {pid}.", file=sys.stderr)
        return 1

    report = {"pid": pid, "process": process_name, "threads": rows}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_process(f"Process: {process_name} (PID {pid})", rows, use_color(args.color))
    return 0


if __name__ == "__main__":
    sys.exit(main())
