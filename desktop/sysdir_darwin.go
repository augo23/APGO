//go:build darwin

package main

// Where the PRIVILEGED side of APGO lives on macOS.
//
// The overlay client runs as root. Everything root runs, writes to or hands
// out — its binary, its log, its pid file, its control socket, the boot
// daemon's plist — must live somewhere only root can modify. It used to be
// ~/.apgo, which any program running as the logged-in user can change, and
// that made several one-step root escalations possible:
//
//   - replace overlay-client.log with a symlink: launchd (and the shell
//     redirect at Connect) open it AS ROOT and append to whatever it points at;
//   - replace control.sock with a symlink: the client chowns/chmods its socket
//     path as root, i.e. hands the target file to the user;
//   - write any pid into client.pid: Disconnect `kill`s it as root;
//   - edit the staged boot-daemon.plist between write and the privileged cp.
//
// /Library/Application Support is root-owned, so a user cannot pre-create or
// symlink APGO inside it; prepareSysDirScript still refuses anything that is
// not a real directory.

import (
	"fmt"
	"os"
	"path/filepath"
)

const sysDirPath = "/Library/Application Support/APGO"

func sysDir() string          { return sysDirPath }
func sysBinDir() string       { return filepath.Join(sysDir(), "bin") }
func controlSocket() string   { return filepath.Join(sysDir(), "control.sock") }
func logPath() string         { return filepath.Join(sysDir(), "overlay-client.log") }
func pidPath() string         { return filepath.Join(sysDir(), "client.pid") }
func installedClient() string { return filepath.Join(sysBinDir(), clientExeName) }

// socketOwnerEnv tells the root client which user may use the control socket.
// It chowns the socket to this uid:gid instead of to the directory's owner
// (which is now root).
func socketOwnerEnv() string { return fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) }

// prepareSysDirScript returns a shell fragment, run AS ROOT, that creates the
// root-owned state directory, installs a root-owned copy of the client binary
// into it (the boot daemon and Connect run THAT copy, never a file the user can
// swap), and pre-creates the log owned by the user so the menu-bar app can read
// it while nobody but root can replace it.
func prepareSysDirScript() string {
	d, bin, dst := q(sysDir()), q(sysBinDir()), q(installedClient())
	tmp := q(installedClient() + ".new")
	return fmt.Sprintf(
		"set -e; "+
			"for p in %[1]s %[2]s; do if [ -L \"$p\" ] || { [ -e \"$p\" ] && [ ! -d \"$p\" ]; }; then rm -f \"$p\"; fi; done; "+
			"mkdir -p %[2]s; chown -h root:wheel %[1]s %[2]s; chmod 755 %[1]s %[2]s; "+
			"rm -f %[4]s; cp %[5]s %[4]s; chown root:wheel %[4]s; chmod 755 %[4]s; mv -f %[4]s %[3]s; "+
			"for f in %[6]s %[7]s; do if [ -L \"$f\" ]; then rm -f \"$f\"; fi; done; "+
			"touch %[6]s; chown -h %[8]d:%[9]d %[6]s; chmod 600 %[6]s; "+
			"set +e; ",
		d, bin, dst, tmp, q(clientBinary()), q(logPath()), q(pidPath()), os.Getuid(), os.Getgid())
}
