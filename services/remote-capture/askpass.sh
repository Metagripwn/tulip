#!/bin/sh

# SPDX-FileCopyrightText: 2026 Tulip contributors
#
# SPDX-License-Identifier: AGPL-3.0-only

# OpenSSH calls this helper only for the password prompt. The password is kept
# in a mode-0600 file mounted into the remote-capture container, never in an
# environment variable, Compose file, command line, or log.
set -eu
cat "${REMOTE_SSH_PASSWORD_FILE:?missing REMOTE_SSH_PASSWORD_FILE}"
