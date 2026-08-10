//go:build darwin

package main

// notify_darwin.go posts user notifications from THIS app's own process using
// the native Cocoa API, so the banner shows the APGO icon.
//
// Why not osascript? `osascript -e 'display notification …'` runs inside Apple's
// Script Editor helper, so macOS attributes the banner to Script Editor and
// shows ITS icon (and it needs Script Editor's own notification permission).
// Delivering the notification from our bundled process makes macOS use this
// app's bundle icon (the APGO.icns packaged by macos/build.sh) automatically.
//
// NSUserNotification is deprecated (superseded by UserNotifications.framework)
// but still delivers, needs no entitlement, and works for a plain bundled app —
// the right trade-off for a tiny menu-bar utility. For the icon to appear the
// binary must run from inside APGO.app with an icon; see macos/build.sh.

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>
#import <Cocoa/Cocoa.h>

static void apgoNotify(const char *title, const char *msg) {
    @autoreleasepool {
        NSUserNotification *n = [[NSUserNotification alloc] init];
        n.title = [NSString stringWithUTF8String:title];
        n.informativeText = [NSString stringWithUTF8String:msg];
        [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:n];
    }
}
*/
import "C"

import "unsafe"

func notify(msg string) {
	ctitle := C.CString("APGO")
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(ctitle))
	defer C.free(unsafe.Pointer(cmsg))
	C.apgoNotify(ctitle, cmsg)
}
