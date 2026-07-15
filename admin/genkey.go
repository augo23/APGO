package main

// genkey.go implements `overlay-admin genkey` — the CLI path to create the
// admin signing key. The web dashboard's "Admin key" page uses the same
// genAdminKey() (in adminkey.go). Run the CLI via:
//
//   echo -n 'your-admin-password' | podman exec -i overlay-admin overlay-admin genkey

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func runGenKey() {
	pub, err := genAdminKey(string(readPasswordFromStdin()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Admin key created.")
	fmt.Println()
	fmt.Println("It is auto-seeded to peers. You can also pin it on every node with:")
	fmt.Println("  ADMIN_PUBLIC_KEY=" + pub)
	fmt.Println()
	fmt.Println("Store the password safely — it cannot be recovered and every revoke/restore needs it.")
}

func readPasswordFromStdin() []byte {
	data, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	return []byte(strings.TrimRight(string(data), "\r\n"))
}
