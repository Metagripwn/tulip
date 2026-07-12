#!/bin/sh

# SPDX-FileCopyrightText: 2026 Tulip contributors
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

required() {
    name="$1"
    eval "value=\${$name:-}"
    if [ -z "$value" ]; then
        echo "remote-capture: missing required environment variable: $name" >&2
        exit 1
    fi
}

# Quote one value for the POSIX shell which OpenSSH invokes on the remote end.
quote_remote() {
    printf "'"
    printf "%s" "$1" | sed "s/'/'\\\\''/g"
    printf "'"
}

required REMOTE_SSH_HOST
required REMOTE_SSH_USER
required REMOTE_CAPTURE_INTERFACE

case "${REMOTE_SSH_AUTH:-password}" in
    key)
        if [ ! -r "$REMOTE_SSH_IDENTITY_FILE" ]; then
            echo "remote-capture: SSH identity is not readable: $REMOTE_SSH_IDENTITY_FILE" >&2
            exit 1
        fi
        ssh_auth_args="-i $REMOTE_SSH_IDENTITY_FILE -o BatchMode=yes -o IdentitiesOnly=yes"
        ;;
    password)
        if [ ! -r "$REMOTE_SSH_PASSWORD_FILE" ]; then
            echo "remote-capture: SSH password file is not readable: $REMOTE_SSH_PASSWORD_FILE" >&2
            exit 1
        fi
        # Force askpass even though the service has no interactive terminal.
        # This lets OpenSSH reconnect without exposing the password in ps(1).
        export SSH_ASKPASS=/app/askpass.sh
        export SSH_ASKPASS_REQUIRE=force
        export DISPLAY=tulip-remote-capture
        ssh_auth_args="-o BatchMode=no -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1"
        ;;
    *)
        echo "remote-capture: REMOTE_SSH_AUTH must be 'password' or 'key'" >&2
        exit 1
        ;;
esac

case "$REMOTE_CAPTURE_SNAPLEN" in
    ''|*[!0-9]*)
        echo "remote-capture: REMOTE_CAPTURE_SNAPLEN must be a non-negative integer" >&2
        exit 1
        ;;
esac

interface_quoted="$(quote_remote "$REMOTE_CAPTURE_INTERFACE")"
filter_quoted="$(quote_remote "$REMOTE_CAPTURE_FILTER")"

# SSH_CONNECTION is set by sshd as "client-ip client-port server-ip server-port".
# The remote command derives the management connection from it and excludes it
# before passing a user supplied BPF expression to tcpdump. Without this,
# tcpdump can capture the SSH packets that carry its own PCAP output.
remote_command='set -- $SSH_CONNECTION; client_ip=$1; ssh_port=$4; capture_filter="not (host $client_ip and tcp port $ssh_port)"; '
if [ -n "$REMOTE_CAPTURE_FILTER" ]; then
    remote_command="$remote_command user_filter=$filter_quoted; capture_filter=\"\$capture_filter and (\$user_filter)\";"
fi

if [ "$REMOTE_CAPTURE_USE_SUDO" = "true" ]; then
    remote_command="$remote_command exec sudo -n tcpdump"
else
    remote_command="$remote_command exec tcpdump"
fi
remote_command="$remote_command -n -i $interface_quoted -s $REMOTE_CAPTURE_SNAPLEN -U -w - -- \"\$capture_filter\""

ssh_args="-T -n -p $REMOTE_SSH_PORT $ssh_auth_args \
    -o StrictHostKeyChecking=yes \
    -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
    -o ConnectTimeout=15"

echo "remote-capture: streaming ${REMOTE_SSH_USER}@${REMOTE_SSH_HOST}:${REMOTE_CAPTURE_INTERFACE} to local ingestor" >&2

while true; do
    # shellcheck disable=SC2086
    ssh $ssh_args "${REMOTE_SSH_USER}@${REMOTE_SSH_HOST}" "$remote_command" | nc ingestor 9999
    status=$?
    echo "remote-capture: stream ended (status $status); retrying in 5 seconds" >&2
    sleep 5
done
