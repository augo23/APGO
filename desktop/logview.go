package main

// logview.go provides tailLog, used by the admin panel's /api/logs endpoint to
// show the client log in the web dashboard. (The standalone "Open log" menu item
// was removed — logs now live in the admin panel.)

import (
	"io"
	"os"
	"strings"
)

func tailLog(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return "(no log yet — click Connect)"
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "(cannot read log)"
	}
	start := int64(0)
	if st.Size() > maxBytes {
		start = st.Size() - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "(cannot read log)"
	}
	data, _ := io.ReadAll(f)
	s := string(data)
	if start > 0 {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:] // drop partial first line
		}
	}
	if strings.TrimSpace(s) == "" {
		return "(log is empty)"
	}
	return s
}
