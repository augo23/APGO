package main

// trackers.go backs the admin UI's tracker manager. Trackers can be added or
// removed live; the effective list is persisted to a managed file which, once it
// exists, is authoritative over the config list (so removals stick). The announce
// loops re-read it every tick, so changes take effect without a restart.

import (
	"os"
	"strings"
	"sync/atomic"
)

var (
	gConfigTrackers []string // the base list from the config file / defaults
	gTrackerFile    string   // path to the managed tracker file
)

func trackerFilePath() string {
	if p := os.Getenv("TRACKERS_FILE"); p != "" {
		return p
	}
	return "/state/trackers.txt"
}

// managedTrackerFile returns the managed file path IF it exists on disk (i.e. an
// admin has edited the list), else "".
func managedTrackerFile() string {
	if gTrackerFile == "" {
		return ""
	}
	if _, err := os.Stat(gTrackerFile); err == nil {
		return gTrackerFile
	}
	return ""
}

// currentTrackers returns the effective tracker list shown in the admin UI.
func currentTrackers() []string {
	return loadTrackerList(&ClientConfig{Trackers: gConfigTrackers})
}

// saveTrackers writes a cleaned, de-duplicated list to the managed file, making
// it authoritative from now on.
func saveTrackers(list []string) error {
	out := []string{}
	seen := map[string]bool{}
	for _, t := range list {
		s := strings.TrimSpace(t)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	path := gTrackerFile
	if path == "" {
		path = trackerFilePath()
		gTrackerFile = path
	}
	tmp := path + ".tmp"
	// One tracker per line, separated by ONE blank line — the canonical format
	// of config/trackers.txt, shared by every platform's tracker editor.
	// (Readers skip blank lines, so files in either format parse fine.)
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n\n")+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- tracker discovery on/off ---------------------------------------------

// trackersOn gates tracker announces without discarding the list. Off means the
// node keeps its trackers configured but stops announcing to them -- so an
// operator who has the DHT or a rendezvous server can drop the public-tracker
// traffic (and the public record of this node's address that comes with it)
// and switch it back on later without retyping anything.
var trackersOn atomicBoolDefaultTrue

func setTrackersEnabled(on bool) { trackersOn.Store(on) }
func trackersEnabled() bool      { return trackersOn.Load() }

// atomicBoolDefaultTrue is an atomic bool whose ZERO VALUE reads as true.
// Tracker discovery has always been on, so an unset field must keep it on:
// a plain atomic.Bool would silently disable trackers on every node that has
// never been configured, which is a regression disguised as a default.
type atomicBoolDefaultTrue struct{ off atomic.Bool }

func (a *atomicBoolDefaultTrue) Store(v bool) { a.off.Store(!v) }
func (a *atomicBoolDefaultTrue) Load() bool   { return !a.off.Load() }
