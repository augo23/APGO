//go:build !windows

package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// secureControlSocket restricts who can connect to the control socket.
//
// The socket used to be chmod 0666, i.e. any local user could drive the
// daemon — read the PSK from /api/join-info, set the trusted admin key, push a
// sealed admin key — relying only on the parent directory's permissions. It is
// now owned by the OWNER of the directory it lives in (or CONTROL_SOCKET_OWNER),
// and only that owner (and root) may connect:
//
//   - macOS/Linux desktop: the client runs as root, the socket sits in the
//     user's ~/.apgo, so the user (and their menu-bar app) keeps access and
//     other local users lose it;
//   - containers: the shared volume belongs to root, as do both containers.
//
// CONTROL_SOCKET_MODE (octal, e.g. "0666") overrides the mode for unusual
// deployments where the admin panel runs as a different, unrelated user.
//
// SECURITY: this runs as root and acts on a PATH. If that path's directory is
// writable by an unprivileged user (the old ~/.apgo layout), the socket can be
// swapped for a symlink between Listen and here, and a following chown/chmod
// would hand the link's TARGET to that user. So:
//
//   - the socket is Lstat'ed and must still be a socket;
//   - ownership changes use Lchown (never follows a link);
//   - chmod (which has no no-follow form on Linux) is only done when an explicit
//     CONTROL_SOCKET_MODE asks for it. It isn't needed otherwise: the socket is
//     created 0755 under the default umask, and connecting needs WRITE
//     permission, so only its owner (and root) can use it.
//
// CONTROL_SOCKET_OWNER=uid:gid names the owner explicitly. The macOS desktop
// app sets it, because the socket now lives in a root-owned directory
// (/Library/Application Support/APGO) whose owner is no longer the user.
func secureControlSocket(path string) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		log.Printf("[control] %s is not our socket any more (replaced?) — leaving its permissions alone", path)
		return
	}
	if os.Geteuid() == 0 {
		uid, gid, ok := -1, -1, false
		if v := os.Getenv("CONTROL_SOCKET_OWNER"); v != "" {
			if u, g, found := strings.Cut(v, ":"); found {
				ui, e1 := strconv.Atoi(u)
				gi, e2 := strconv.Atoi(g)
				if e1 == nil && e2 == nil && ui >= 0 && gi >= 0 {
					uid, gid, ok = ui, gi, true
				}
			}
			if !ok {
				log.Printf("[control] CONTROL_SOCKET_OWNER %q is not uid:gid — ignoring", v)
			}
		}
		if !ok {
			if dfi, err := os.Stat(filepath.Dir(path)); err == nil {
				if st, sok := dfi.Sys().(*syscall.Stat_t); sok {
					uid, gid, ok = int(st.Uid), int(st.Gid), true
				}
			}
		}
		if ok {
			if err := os.Lchown(path, uid, gid); err != nil {
				log.Printf("[control] could not hand %s to %d:%d: %v", path, uid, gid, err)
			}
		}
	}
	if v := os.Getenv("CONTROL_SOCKET_MODE"); v != "" {
		m, err := strconv.ParseUint(v, 8, 32)
		if err != nil || m > 0o777 {
			log.Printf("[control] CONTROL_SOCKET_MODE %q is not an octal mode — ignoring", v)
			return
		}
		if err := os.Chmod(path, os.FileMode(m)); err != nil {
			log.Printf("[control] chmod %s: %v", path, err)
		}
	}
}
