package main

// Symlink-safe file writes.
//
// On macOS and Windows desktops the client runs as root / SYSTEM but keeps its
// state in the logged-in user's ~/.apgo, a directory that any program running
// as that user can modify. A plain os.WriteFile there follows symlinks, so a
// user-level process could plant `~/.apgo/provisions.json.tmp -> /etc/...` and
// have the privileged client overwrite an arbitrary system file. These helpers
// refuse to write THROUGH a link: an existing link at the path is removed
// first, and on Unix the open itself uses O_NOFOLLOW, so a link raced
// back in between fails the write instead of redirecting it.

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileNoFollow is os.WriteFile that never writes through a symlink.
func writeFileNoFollow(name string, data []byte, perm os.FileMode) error {
	if err := removeIfLink(name); err != nil {
		return err
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|oNoFollow, perm)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// mkdirAllNoLink is os.MkdirAll that refuses a result (or parent) that is a
// symlink or junction, so files are never created inside a redirected dir.
func mkdirAllNoLink(dir string, perm os.FileMode) error {
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	for _, d := range []string{dir, filepath.Dir(dir)} {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("%s is not a plain directory (symlink or junction?) — refusing to write into it", d)
		}
	}
	return nil
}

// removeIfLink deletes name if it is a symlink (or, on Windows, a junction or
// other reparse point, which Go reports as ModeIrregular). Removing a link
// deletes the link itself, never its target.
func removeIfLink(name string) error {
	fi, err := os.Lstat(name)
	if err != nil || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
		return nil
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("%s is a link and could not be removed: %w", name, err)
	}
	return nil
}
