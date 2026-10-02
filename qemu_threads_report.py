#!/usr/bin/env python3
# Copyright (C) 2026 Savoir-faire Linux Inc.
# SPDX-License-Identifier: Apache-2.0
"""Report QEMU/KVM thread affinity and scheduler state from procfs."""

import argparse
import json
import os
import re
import sys

from _process_threads import PROC, process_rows, print_process, read_text, use_color


def vm_name(cmdline):
    arguments = cmdline.split("\0")
    for index, argument in enumerate(arguments[:-1]):
        if argument == "-name":
            name = arguments[index + 1]
            # libvirt normally emits guest=<name>,debug-threads=on.
            for option in name.split(","):
                if option.startswith("guest="):
                    return option.removeprefix("guest=")
            return name.split(",", 1)[0]
    return "<unnamed>"


def is_qemu(pid, comm):
    cmdline = read_text(PROC / str(pid) / "cmdline") or ""
    executable = os.path.basename(cmdline.split("\0", 1)[0])
    return executable.startswith("qemu") or comm.startswith("qemu")


def process_ids():
    try:
        entries = PROC.iterdir()
        for entry in entries:
            if entry.name.isdecimal():
                yield int(entry.name)
    except PermissionError:
        return


def main():
    parser = argparse.ArgumentParser(
        description="Show QEMU VM and host KVM task CPU affinity and scheduler state."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="also show QEMU/KVM task groups with no detectable VM name",
    )
    parser.add_argument(
        "vm_name",
        nargs="?",
        help="show only this VM and its associated kvm-pit task",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="color human output (default: auto)",
    )
    args = parser.parse_args()
    colored = use_color(args.color)

    qemu_processes = []
    other_processes = []
    kvm_pit_processes = {}
    qemu_names = {}
    other_pattern = re.compile(r"^(?:qemu|kvm|vhost)", re.IGNORECASE)

    for pid in process_ids():
        comm = read_text(PROC / str(pid) / "comm")
        if comm is None:
            continue
        if is_qemu(pid, comm):
            qemu_processes.append(pid)
            cmdline = read_text(PROC / str(pid) / "cmdline") or ""
            qemu_names[pid] = vm_name(cmdline)
        elif other_pattern.match(comm):
            match = re.fullmatch(r"kvm-pit/(\d+)", comm)
            if match:
                qemu_pid = int(match.group(1))
                kvm_pit_processes.setdefault(qemu_pid, []).append(pid)
            else:
                other_processes.append(pid)

    groups = []

    def add_group(pid, title):
        groups.append({"pid": pid, "name": title})

    for pid in sorted(qemu_processes):
        name = qemu_names[pid]
        if args.vm_name is not None and name != args.vm_name:
            continue
        if name != "<unnamed>" or args.all:
            add_group(pid, f"VM: {name}")
            for pit_pid in kvm_pit_processes.pop(pid, []):
                add_group(pit_pid, f"KVM PIT for VM: {name} (QEMU PID {pid})")

    if args.vm_name is None:
        for pid in sorted(other_processes):
            comm = read_text(PROC / str(pid) / "comm") or "?"
            add_group(pid, f"Other QEMU/KVM task: {comm}")

        for qemu_pid in sorted(kvm_pit_processes):
            for pit_pid in kvm_pit_processes[qemu_pid]:
                add_group(
                    pit_pid,
                    f"KVM PIT: kvm-pit/{qemu_pid} (QEMU PID {qemu_pid}, VM not found)",
                )

    if not groups:
        if args.vm_name is None:
            print("No QEMU VM or KVM task found.", file=sys.stderr)
        else:
            print(f"VM not found: {args.vm_name}", file=sys.stderr)
        return 1

    clock_ticks = os.sysconf("SC_CLK_TCK")
    uptime = float((read_text(PROC / "uptime") or "0").split()[0])
    for group in groups:
        group["threads"] = process_rows(group["pid"], uptime, clock_ticks)

    if args.json:
        print(json.dumps({"groups": groups}, indent=2, sort_keys=True))
    else:
        for group in groups:
            print_process(f"{group['name']} (PID {group['pid']})", group["threads"], colored)
    return 0


if __name__ == "__main__":
    sys.exit(main())
