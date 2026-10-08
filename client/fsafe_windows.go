//go:build windows

package main

// Windows has no O_NOFOLLOW; removeIfLink (which sees symlinks and
// junctions via Lstat) is the protection there.
const oNoFollow = 0
