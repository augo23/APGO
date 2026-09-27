//go:build !windows

package overlaymobile

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// secureControlSocket restricts who can connect to the control socket.
//
// The socket used to be chmod 0666, i.e. any local user could drive the
// daemon — read the PSK from /api/join-info, set the trusted admin key, push a
// sealed admin key — relying only on the parent directory's permissions. It is
// now owned by the OWNER of the directory it lives in and mode 0660:
//
//   - macOS/Linux desktop: the client runs as root, the socket sits in the
//     user's ~/.apgo, so the user (and their menu-bar app) keeps access and
//     other local users lose it;
//   - containers: the shared volume belongs to root, as do both containers.
//
// CONTROL_SOCKET_MODE (octal, e.g. "0666") overrides the mode for unusual
// deployments where the admin panel runs as a different, unrelated user.
func secureControlSocket(path string) {
	mode := os.FileMode(0o660)
	if v := os.Getenv("CONTROL_SOCKET_MODE"); v != "" {
		if m, err := strconv.ParseUint(v, 8, 32); err == nil && m <= 0o777 {
			mode = os.FileMode(m)
		} else {
			log.Printf("[control] CONTROL_SOCKET_MODE %q is not an octal mode — using 0660", v)
		}
	}
	if fi, err := os.Stat(filepath.Dir(path)); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
			if err := os.Chown(path, int(st.Uid), int(st.Gid)); err != nil {
				log.Printf("[control] could not hand %s to its directory's owner: %v", path, err)
			}
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		log.Printf("[control] chmod %s: %v", path, err)
	}
}
