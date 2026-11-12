// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package secrets

import "syscall"

// noFollow makes open fail on a symbolic link. The server is Linux-only (systemd
// units, /etc paths), so there is no portable fallback to maintain.
const noFollow = syscall.O_NOFOLLOW
