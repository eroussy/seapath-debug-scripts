#!/usr/bin/env python3
# Copyright (C) 2026 Savoir-faire Linux Inc.
# SPDX-License-Identifier: Apache-2.0
"""Add, remove, or replace SSH public keys for SEAPATH users."""

import argparse
import base64
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


USERS = ("admin", "ansible", "root")
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
    "IdentityFile",
)
PRIVATE_KEY_HEADER = "-----BEGIN"

REMOTE_SCRIPT = r"""
set -eu

action=$1
key_type=$2
key_data=$3
key_line=$4

for account in admin ansible root; do
    entry=$(getent passwd "$account") || {
        echo "Account not found: $account" >&2
        exit 1
    }
    home=$(printf '%s\n' "$entry" | cut -d: -f6)
    ssh_directory=$home/.ssh
    authorized_keys=$ssh_directory/authorized_keys

    umask 077
    mkdir -p "$ssh_directory"
    chown "$account" "$ssh_directory"
    chmod 700 "$ssh_directory"
    touch "$authorized_keys"
    chown "$account" "$authorized_keys"
    chmod 600 "$authorized_keys"

    case "$action" in
        add)
            if awk -v type="$key_type" -v data="$key_data" \
                '{ for (i = 1; i < NF; i++) if ($i == type && $(i + 1) == data) found = 1 }
                 END { exit !found }' \
                "$authorized_keys"; then
                echo "$account: key already present"
                continue
            fi
            printf '%s\n' "$key_line" >> "$authorized_keys"
            echo "$account: key added"
            ;;
        remove)
            temporary=$(mktemp "$ssh_directory/.authorized_keys.XXXXXX")
            trap 'rm -f "$temporary"' EXIT HUP INT TERM
            awk -v type="$key_type" -v data="$key_data" \
                '{ matched = 0
                   for (i = 1; i < NF; i++) if ($i == type && $(i + 1) == data) matched = 1
                   if (!matched) print }' "$authorized_keys" > "$temporary"
            chown "$account" "$temporary"
            chmod 600 "$temporary"
            mv "$temporary" "$authorized_keys"
            trap - EXIT HUP INT TERM
            echo "$account: matching key removed"
            ;;
        replace)
            temporary=$(mktemp "$ssh_directory/.authorized_keys.XXXXXX")
            trap 'rm -f "$temporary"' EXIT HUP INT TERM
            printf '%s\n' "$key_line" > "$temporary"
            chown "$account" "$temporary"
            chmod 600 "$temporary"
            mv "$temporary" "$authorized_keys"
            trap - EXIT HUP INT TERM
            echo "$account: authorized_keys replaced"
            ;;
        *) echo "Unsupported action: $action" >&2; exit 2 ;;
    esac
done
"""


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
        messages = result.stderr.strip().splitlines()
        raise RuntimeError(messages[-1] if messages else f"ssh -G exited with status {result.returncode}")

    config = {}
    for line in result.stdout.splitlines():
        option, separator, value = line.partition(" ")
        if separator:
            config[option.lower()] = value
    return config


def ssh_command(target, login_key, config, remote_command):
    command = ["ssh", "-F", "/dev/null"]
    for option in CONNECTION_OPTIONS:
        if option == "IdentityFile" and login_key:
            continue
        value = config.get(option.lower())
        if value and value.lower() != "none":
            command.extend((SSH_OPTION, f"{option}={value}"))
    command.extend(
        [
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
        "LogLevel=ERROR",
        "-l",
        "admin",
        ]
    )
    if login_key:
        command.extend(("-i", str(login_key)))
    return command + [target, remote_command]


def is_private_key_text(text):
    return text.startswith(PRIVATE_KEY_HEADER) and "PRIVATE KEY-----" in text


def is_public_key_text(text):
    fields = text.split()
    if len(fields) < 2:
        return False
    try:
        base64.b64decode(fields[1], validate=True)
    except ValueError:
        return False
    return True


def read_key_text(path, option):
    try:
        return path.read_text()
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(f"cannot read {option} {path}: {error}") from error


def read_public_key(path):
    text = read_key_text(path, "--public-key")
    if is_private_key_text(text.lstrip()):
        raise ValueError(f"{path} contains a private key; --public-key requires a public key")

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"public key file {path} must contain exactly one non-empty line")

    fields = lines[0].split()
    if not is_public_key_text(lines[0]):
        raise ValueError(f"invalid public key in {path}")
    return lines[0], fields[0], fields[1]


def validate_private_key(identity):
    key_text = read_key_text(identity, "--key")
    key_lines = [line.strip() for line in key_text.splitlines() if line.strip()]
    if len(key_lines) == 1 and is_public_key_text(key_lines[0]):
        raise ValueError(f"{identity} contains a public key; --key requires a private key")


def derive_public_key(identity):
    try:
        result = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(identity)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as error:
        raise ValueError(str(error)) from error
    if result.returncode:
        message = result.stderr.strip().splitlines()
        detail = message[-1] if message else f"ssh-keygen exited with status {result.returncode}"
        raise ValueError(detail)
    line = result.stdout.strip()
    fields = line.split()
    if not is_public_key_text(line):
        raise ValueError("ssh-keygen returned invalid public key")
    return line, fields[0], fields[1]


def remote_command(action, key_type, key_data, key_line):
    arguments = (action, key_type, key_data, key_line)
    return "sudo -n /bin/sh -s -- " + " ".join(shlex.quote(argument) for argument in arguments)


def main():
    parser = argparse.ArgumentParser(
        description="Manage SSH public keys for standard SEAPATH accounts through admin SSH access."
    )
    parser.add_argument("target", help="IP address, hostname, or Host alias from SSH config")
    parser.add_argument("action", choices=("add", "remove", "replace"), help="key operation")
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--key",
        type=Path,
        help="private key whose derived public key is managed",
    )
    key_group.add_argument(
        "--public-key",
        type=Path,
        help="public key to manage",
    )
    parser.add_argument(
        "--login-key",
        type=Path,
        help="private key used to connect as admin; default: IdentityFile from SSH config",
    )
    args = parser.parse_args()

    if shutil.which("ssh") is None:
        parser.error("ssh command not found in PATH")
    try:
        managed_key = args.key.expanduser() if args.key else None
        if managed_key:
            validate_private_key(managed_key)
        if args.public_key:
            key_line, key_type, key_data = read_public_key(args.public_key.expanduser())
        else:
            key_line, key_type, key_data = derive_public_key(managed_key)
        config = ssh_config(args.target)
    except (RuntimeError, ValueError) as error:
        parser.error(str(error))

    login_key = args.login_key.expanduser() if args.login_key else None
    if login_key:
        try:
            validate_private_key(login_key)
        except ValueError as error:
            parser.error(str(error))

    command = remote_command(args.action, key_type, key_data, key_line)
    try:
        result = subprocess.run(
            ssh_command(args.target, login_key, config, command),
            input=REMOTE_SCRIPT,
            text=True,
            check=False,
        )
    except OSError as error:
        print(f"cannot start ssh: {error}", file=sys.stderr)
        return 1
    if result.returncode:
        print(f"operation failed (ssh exit status {result.returncode})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
