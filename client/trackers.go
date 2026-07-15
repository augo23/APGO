package main

// trackers.go backs the admin UI's tracker manager. Trackers can be added or
// removed live; the effective list is persisted to a managed file which, once it
// exists, is authoritative over the config list (so removals stick). The announce
// loops re-read it every tick, so changes take effect without a restart.

import (
	"os"
	"strings"
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
