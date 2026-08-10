package overlaymobile

// On mobile the OS owns the tunnel, so there are no per-OS TUN files. tunName is
// defined in those files on the desktop/server client; the exit (Linux) path
// references it and also compiles for android, so provide a definition here.
// It stays empty on mobile (a phone is never an exit node).
var tunName string
