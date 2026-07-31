#!/usr/bin/env python3
# Copyright (C) 2026 Savoir-faire Linux Inc.
# SPDX-License-Identifier: Apache-2.0
"""Test SSH public-key authentication for standard SEAPATH users."""

import argparse
import base64
import os
import select
import shutil
import subprocess
import sys
import tempfile
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
        if is_encrypted_private_key(entry):
            print(f"Skipping encrypted private key: {entry}", file=sys.stderr)
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


def is_encrypted_private_key(path):
    """Return whether path contains an encrypted supported private key format."""
    try:
        contents = path.read_bytes()
    except PermissionError:
        return False
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in contents:
        return True
    if b"Proc-Type: 4,ENCRYPTED" in contents:
        return True

    lines = contents.splitlines()
    if not lines or lines[0] != b"-----BEGIN OPENSSH PRIVATE KEY-----":
        return False
    try:
        encoded = b"".join(line for line in lines[1:] if not line.startswith(b"-----"))
        data = base64.b64decode(encoded, validate=True)
        if not data.startswith(b"openssh-key-v1\0"):
            return False
        offset = len(b"openssh-key-v1\0")
        cipher_length = int.from_bytes(data[offset : offset + 4], "big")
        cipher = data[offset + 4 : offset + 4 + cipher_length]
    except (ValueError, IndexError):
        return False
    return cipher != b"none"


def agent_public_keys():
    """Return public keys currently available through ssh-agent."""
    try:
        result = subprocess.run(
            ["ssh-add", "-L"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return []
    if result.returncode:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


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


def ssh_command(target, user, key, timeout, config, use_agent=False):
    command = [
        "ssh",
        "-F",
        "/dev/null",
    ]
    for option in CONNECTION_OPTIONS:
        value = config.get(option.lower())
        if value and value.lower() != "none":
            command.extend((SSH_OPTION, f"{option}={value}"))
    if not use_agent:
        command.extend((SSH_OPTION, "IdentityAgent=none"))
    return command + [
        SSH_OPTION,
        "BatchMode=yes",
        SSH_OPTION,
        "IdentitiesOnly=yes",
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


def test_key(target, user, key, timeout, config, use_agent=False):
    try:
        process = subprocess.Popen(
            ssh_command(target, user, key, timeout, config, use_agent),
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
        if is_encrypted_private_key(key):
            parser.error(f"encrypted private SSH key: {key}")
        keys = [key]
    else:
        try:
            keys = private_keys(args.ssh_dir.expanduser())
        except RuntimeError as error:
            parser.error(str(error))
    agent_keys = [] if args.key else agent_public_keys()
    if not keys and not agent_keys:
        print(f"No private SSH keys found in {args.ssh_dir.expanduser()}", file=sys.stderr)
        return 1

    target = f"Target: {args.target}"
    key_count = f"Private keys: {len(keys)}"
    print(colorize(target, "cyan", "bold") if colored else target)
    print(colorize(key_count, "cyan") if colored else key_count)
    if agent_keys:
        agent_count = f"SSH-agent keys: {len(agent_keys)}"
        print(colorize(agent_count, "cyan") if colored else agent_count)
    found = False
    with tempfile.TemporaryDirectory(prefix="ssh-key-test-") as directory:
        agent_identities = []
        for index, public_key in enumerate(agent_keys, start=1):
            path = Path(directory) / f"agent-{index}.pub"
            path.write_text(f"{public_key}\n", encoding="utf-8")
            agent_identities.append((path, f"ssh-agent: {public_key}"))
        identities = [(key, str(key), False) for key in keys]
        identities.extend((key, label, True) for key, label in agent_identities)
        for user in USERS:
            heading = f"\nUser: {user}"
            print(colorize(heading, "cyan", "bold") if colored else heading)
            for key, label, use_agent in identities:
                success, reason = test_key(
                    args.target, user, key, args.timeout, config, use_agent
                )
                if success:
                    status = "  SUCCESS"
                    if colored:
                        status = colorize(status, "green", "bold")
                    print(f"{status}  {label}")
                    found = True
                else:
                    status = "  FAILED "
                    if colored:
                        status = colorize(status, "red", "bold")
                    print(f"{status}  {label}")
                    if args.debug:
                        detail = f"           {reason}"
                        print(colorize(detail, "yellow") if colored else detail)

    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
