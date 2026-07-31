#!/usr/bin/env python3
# Copyright (C) 2026 Savoir-faire Linux Inc.
# SPDX-License-Identifier: Apache-2.0
"""Test SSH public-key authentication for standard SEAPATH users."""

import argparse
import os
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path


USERS = ("admin", "ansible", "root")
PUBLIC_KEY_SUFFIXES = (".pub", "-cert.pub")
SSH_OPTION = "-o"
CONNECTION_OPTIONS = (
    "Hostname",
    "Port",
    "AddressFamily",
    "BindAddress",
    "ProxyCommand",
    "ProxyJump",
    "HostKeyAlias",
    "StrictHostKeyChecking",
    "UserKnownHostsFile",
    "GlobalKnownHostsFile",
)
COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
}


def colorize(value, *colors):
    return "".join(COLORS[color] for color in colors) + value + COLORS["reset"]


def private_keys(ssh_directory):
    """Return regular files in ssh_directory that can be private SSH keys."""
    keys = []
    try:
        entries = sorted(ssh_directory.iterdir())
    except (FileNotFoundError, PermissionError) as error:
        raise RuntimeError(f"cannot read SSH directory {ssh_directory}: {error}") from error

    for entry in entries:
        if not is_private_key(entry):
            continue
        keys.append(entry)
    return keys


def is_private_key(path):
    if not path.is_file() or path.name.endswith(PUBLIC_KEY_SUFFIXES):
        return False
    try:
        with path.open("rb") as key_file:
            header = key_file.read(64)
    except PermissionError:
        print(f"Skipping unreadable file: {path}", file=sys.stderr)
        return False
    return b"PRIVATE KEY" in header or header.startswith(b"-----BEGIN OPENSSH")


def ssh_config(target):
    try:
        result = subprocess.run(
            ["ssh", "-G", target],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(str(error)) from error
    if result.returncode:
        message = result.stderr.strip().splitlines()
        raise RuntimeError(message[-1] if message else f"ssh -G exited with status {result.returncode}")

    config = {}
    for line in result.stdout.splitlines():
        option, separator, value = line.partition(" ")
        if separator:
            config[option.lower()] = value
    return config


def ssh_command(target, user, key, timeout, config):
    command = [
        "ssh",
        "-F",
        "/dev/null",
    ]
    for option in CONNECTION_OPTIONS:
        value = config.get(option.lower())
        if value and value.lower() != "none":
            command.extend((SSH_OPTION, f"{option}={value}"))
    return command + [
        SSH_OPTION,
        "BatchMode=yes",
        SSH_OPTION,
        "IdentitiesOnly=yes",
        SSH_OPTION,
        "IdentityAgent=none",
        SSH_OPTION,
        "PasswordAuthentication=no",
        SSH_OPTION,
        "KbdInteractiveAuthentication=no",
        SSH_OPTION,
        "PreferredAuthentications=publickey",
        SSH_OPTION,
        f"ConnectTimeout={timeout}",
        SSH_OPTION,
        "ConnectionAttempts=1",
        "-v",
        "-N",
        "-i",
        str(key),
        "-l",
        user,
        target,
    ]


def test_key(target, user, key, timeout, config):
    try:
        process = subprocess.Popen(
            ssh_command(target, user, key, timeout, config),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        return False, str(error)

    deadline = time.monotonic() + timeout
    messages = []
    timed_out = False
    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            readable, _, _ = select.select([process.stderr], [], [], remaining)
            if readable:
                message = process.stderr.readline().strip()
                if message:
                    messages.append(message)
                    if "Authenticated to " in message:
                        return True, ""
            if process.poll() is not None:
                break
        else:
            timed_out = True
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    if timed_out:
        return False, "SSH authentication timed out"
    return False, messages[-1] if messages else f"ssh exited with status {process.returncode}"


def main():
    parser = argparse.ArgumentParser(
        description="Find local SSH private keys that authenticate admin, ansible, or root."
    )
    parser.add_argument("target", help="IP address, hostname, or Host alias from SSH config")
    parser.add_argument(
        "--ssh-dir",
        type=Path,
        default=Path.home() / ".ssh",
        help="directory containing private keys (default: ~/.ssh)",
    )
    parser.add_argument(
        "--key",
        type=Path,
        help="test only this private key instead of scanning --ssh-dir",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="connection timeout per user/key attempt in seconds (default: 5)",
    )
    parser.add_argument("--debug", action="store_true", help="show SSH failure details")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="color human output (default: auto)",
    )
    args = parser.parse_args()
    colored = args.color == "always" or (
        args.color == "auto" and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    )

    if args.timeout < 1:
        parser.error("--timeout must be at least 1")
    if shutil.which("ssh") is None:
        parser.error("ssh command not found in PATH")
    try:
        config = ssh_config(args.target)
    except RuntimeError as error:
        parser.error(f"cannot resolve SSH config for {args.target}: {error}")

    if args.key:
        key = args.key.expanduser()
        if not is_private_key(key):
            parser.error(f"not a readable private SSH key: {key}")
        keys = [key]
    else:
        try:
            keys = private_keys(args.ssh_dir.expanduser())
        except RuntimeError as error:
            parser.error(str(error))
    if not keys:
        print(f"No private SSH keys found in {args.ssh_dir.expanduser()}", file=sys.stderr)
        return 1

    target = f"Target: {args.target}"
    key_count = f"Private keys: {len(keys)}"
    print(colorize(target, "cyan", "bold") if colored else target)
    print(colorize(key_count, "cyan") if colored else key_count)
    found = False
    for user in USERS:
        heading = f"\nUser: {user}"
        print(colorize(heading, "cyan", "bold") if colored else heading)
        for key in keys:
            success, reason = test_key(args.target, user, key, args.timeout, config)
            if success:
                status = "  SUCCESS"
                if colored:
                    status = colorize(status, "green", "bold")
                print(f"{status}  {key}")
                found = True
            else:
                status = "  FAILED "
                if colored:
                    status = colorize(status, "red", "bold")
                print(f"{status}  {key}")
                if args.debug:
                    detail = f"           {reason}"
                    print(colorize(detail, "yellow") if colored else detail)

    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
