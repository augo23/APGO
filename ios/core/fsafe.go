package overlaymobile

import (
	"errors"
	"os"
)

// writeFileNoFollow writes name, refusing to write THROUGH a symlink at that
// path (the desktop client's helper of the same name; dht.go uses it).
func writeFileNoFollow(name string, data []byte, perm os.FileMode) error {
	if fi, err := os.Lstat(name); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to write through a symlink: " + name)
	}
	return os.WriteFile(name, data, perm)
}
