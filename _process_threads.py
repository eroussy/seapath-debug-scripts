# Copyright (C) 2026 Savoir-faire Linux Inc.
# SPDX-License-Identifier: Apache-2.0
"""Internal shared implementation for per-process thread reports."""

import os
import sys
from pathlib import Path


PROC = Path("/proc")

POLICIES = {
    0: "SCHED_OTHER",
    1: "SCHED_FIFO",
    2: "SCHED_RR",
    3: "SCHED_BATCH",
    5: "SCHED_IDLE",
    6: "SCHED_DEADLINE",
}

COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "cyan": "\033[36m",
    "yellow": "\033[33m",
    "red": "\033[31m",
}


def colorize(value, *colors):
    if not colors:
        return value
    return "".join(COLORS[color] for color in colors) + value + COLORS["reset"]


def scheduler_colors(scheduler):
    if scheduler == "SCHED_FIFO":
        return "red", "bold"
    if scheduler == "SCHED_RR":
        return "yellow", "bold"
    return ()


def read_text(path):
    try:
        return path.read_text().strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def read_status(pid, tid):
    text = read_text(PROC / str(pid) / "task" / str(tid) / "status")
    if text is None:
        return None

    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key] = value.strip()
    return fields


def read_stat(pid, tid):
    text = read_text(PROC / str(pid) / "task" / str(tid) / "stat")
    if text is None:
        return None

    # comm may contain spaces and parentheses. Fields after final ')' are fixed.
    closing_paren = text.rfind(")")
    if closing_paren < 0:
        return None
    fields = text[closing_paren + 2 :].split()
    if len(fields) < 37:
        return None

    # proc(5): utime=field 14, stime=15, nice=19, starttime=22, processor=39.
    # Array starts at field 3.
    try:
        return {
            "cpu_time": int(fields[11]) + int(fields[12]),
            "nice": fields[16],
            "start_time": int(fields[19]),
            "cpu": int(fields[36]),
        }
    except ValueError:
        return None


def scheduler(tid):
    try:
        policy = os.sched_getscheduler(tid)
        rt_priority = os.sched_getparam(tid).sched_priority
    except (AttributeError, OSError):
        return "unknown", "?"
    return POLICIES.get(policy, f"unknown({policy})"), str(rt_priority)


def ps_priority(policy, rt_priority, nice):
    """Return Linux ps-style priority: normal 0-39, RT 41-139."""
    if policy in ("SCHED_FIFO", "SCHED_RR"):
        return str(40 + int(rt_priority))
    try:
        return str(19 + int(nice))
    except ValueError:
        return "?"


def process_rows(pid, uptime=None, clock_ticks=None):
    """Return per-thread data for PID; unreadable or exited threads are skipped."""
    if clock_ticks is None:
        clock_ticks = os.sysconf("SC_CLK_TCK")
    if uptime is None:
        uptime_text = read_text(PROC / "uptime") or "0"
        uptime = float(uptime_text.split()[0])

    task_dir = PROC / str(pid) / "task"
    try:
        tids = sorted(int(entry.name) for entry in task_dir.iterdir() if entry.name.isdecimal())
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return []

    rows = []
    for tid in tids:
        status = read_status(pid, tid)
        stat = read_stat(pid, tid)
        if status is None or stat is None:
            continue
        policy, rt_priority = scheduler(tid)
        priority = ps_priority(policy, rt_priority, stat["nice"])
        elapsed = uptime - stat["start_time"] / clock_ticks
        cpu_percent = (
            stat["cpu_time"] / clock_ticks / elapsed * 100 if elapsed > 0 else None
        )
        rows.append(
            {
                "tid": tid,
                "thread": status.get("Name", "?"),
                "scheduler": policy,
                "rtprio": rt_priority,
                "prio": priority,
                "cpu_percent": cpu_percent,
                "last_cpu": stat["cpu"],
                "affinity": status.get("Cpus_allowed_list", "?"),
            }
        )
    return rows


def print_header(colored):
    header = (
        f"{'TID':>7}  {'THREAD':<24} {'SCHEDULER':<15} {'RTPRIO':>6} "
        f"{'PRIO':>4} {'LAST_CPU':>8}  {'AFFINITY':<12} {'CPU%':>6}"
    )
    print(colorize(header, "bold") if colored else header)


def print_process(title, rows, colored):
    if not rows:
        return

    heading = f"\n=== {title} ==="
    print(colorize(heading, "cyan", "bold") if colored else heading)
    print_header(colored)
    for row in rows:
        tid = f"{row['tid']:>7}"
        thread = f"{row['thread']:<24.24}"
        scheduler_name = f"{row['scheduler']:<15.15}"
        rtprio = f"{row['rtprio']:>6}"
        cpu_percent = (
            f"{row['cpu_percent']:>5.1f}%" if row["cpu_percent"] is not None else "     -"
        )
        last_cpu = f"{row['last_cpu']:>8}"
        affinity = f"{row['affinity']:<12}"
        if colored:
            tid = colorize(tid, "yellow")
            scheduler_name = colorize(scheduler_name, *scheduler_colors(row["scheduler"]))
            if row["scheduler"] in ("SCHED_FIFO", "SCHED_RR"):
                rtprio = colorize(rtprio, "yellow", "bold")
            last_cpu = colorize(last_cpu, "yellow")
            affinity = colorize(affinity, "cyan")
        print(
            f"{tid}  {thread} {scheduler_name} {rtprio} "
            f"{row['prio']:>4} {last_cpu}  {affinity} {cpu_percent}"
        )


def use_color(choice):
    return choice == "always" or (
        choice == "auto" and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    )
