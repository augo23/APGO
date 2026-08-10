import NetworkExtension
import Overlaymobile   // gomobile-generated framework (from ios/core)

// PacketTunnelProvider runs the APGO overlay inside the iOS NetworkExtension.
// The app stores the network config in the tunnel's providerConfiguration; here
// we apply the network settings, hand the utun file descriptor to the Go
// overlay core, and let it run.
//
// Getting the utun fd on iOS is undocumented but stable — the same technique
// WireGuard's iOS app uses: scan low fds for the one whose UTUN_OPT_IFNAME
// getsockopt succeeds and whose interface name matches the packetFlow's.
class PacketTunnelProvider: NEPacketTunnelProvider {

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        guard
            let proto = protocolConfiguration as? NETunnelProviderProtocol,
            let conf = proto.providerConfiguration,
            let json = conf["configJSON"] as? String,
            let overlayIP = conf["overlayIP"] as? String,
            let overlayNet = conf["overlayNetwork"] as? String   // e.g. "10.22.55.0"
        else {
            completionHandler(NSError(domain: "APGO", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing tunnel configuration"]))
            return
        }

        // Assign the overlay IP. In full-VPN mode route EVERYTHING through the
        // tunnel (the Go core forwards internet traffic to the fastest exit);
        // otherwise route only the overlay subnet.
        let fullTunnel = (conf["fullTunnel"] as? Bool) ?? false
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: [overlayIP], subnetMasks: ["255.255.255.0"])
        if fullTunnel {
            ipv4.includedRoutes = [NEIPv4Route.default()]

            // Leak prevention — otherwise traffic doesn't egress ONLY via the
            // chosen exit:
            //  * DNS: force every lookup through the tunnel, or iOS resolves via
            //    the physical interface and DNS leaks past the exit.
            let dns = NEDNSSettings(servers: ["1.1.1.1", "1.0.0.1"])
            dns.matchDomains = [""]   // "" = match all domains
            settings.dnsSettings = dns

            //  * IPv6: the overlay is IPv4-only, so without capturing v6 the OS
            //    sends all v6 traffic straight out the real interface, bypassing
            //    the exit. Capture the v6 default too; the core has no v6 route,
            //    so apps fall back to v4 through the exit (no v6 leak).
            let ipv6 = NEIPv6Settings(addresses: ["fd00:28:55::1"], networkPrefixLengths: [64])
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        } else {
            ipv4.includedRoutes = [NEIPv4Route(destinationAddress: overlayNet,
                                               subnetMask: "255.255.255.0")]
        }
        settings.ipv4Settings = ipv4
        settings.mtu = 1280

        setTunnelNetworkSettings(settings) { [weak self] err in
            guard let self = self else { return }
            if let err = err { completionHandler(err); return }

            let fd = self.tunnelFileDescriptor
            if fd < 0 {
                completionHandler(NSError(domain: "APGO", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "could not obtain utun fd"]))
                return
            }
            // Start the Go overlay over the tunnel fd. OverlaymobileStart is the
            // gomobile-generated wrapper for overlaymobile.Start(fd, json). It is
            // a free C function with an NSError** out-parameter (gomobile does
            // NOT bridge free functions to Swift `throws`), so pass &error and
            // hand any failure straight to the completion handler.
            var startErr: NSError?
            OverlaymobileStart(Int(fd), json, &startErr)
            completionHandler(startErr)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        OverlaymobileStop()
        completionHandler()
    }

    // The app asks the running extension for live data via sendProviderMessage.
    // "peers"   -> the Go core's current session list as JSON (SessionInfo array).
    // "pending" -> an admin-assigned overlay address (CIDR) waiting to be
    //              adopted, or "" if none. The Go core can't re-address the OS
    //              tunnel itself (the app configured NEIPv4Settings), so the app
    //              polls this, updates its stored config, and reconnects —
    //              without it, admin IP re-assignments were silently ignored on
    //              iOS.
    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? ""
        switch cmd {
        case "peers":
            completionHandler?(OverlaymobilePeersJSON().data(using: .utf8))
        case "pending":
            completionHandler?(OverlaymobilePendingAddress().data(using: .utf8))
        case "netstatus":
            // This device's own NAT type / public endpoint / IPv6. NAT type is
            // what decides whether a direct session to a given peer is even
            // possible, so the app can explain a permanent relay instead of
            // leaving it a mystery.
            completionHandler?(OverlaymobileNetworkStatusJSON().data(using: .utf8))
        case "exits":
            // Full-VPN outproxy view: which exits this device knows about,
            // their reachability/latency, and which one is selected — so the
            // app can show WHY "no exit is reachable" instead of a dead end.
            completionHandler?(OverlaymobileExitsJSON().data(using: .utf8))
        default:
            completionHandler?(nil)
        }
    }

    // Locate the utun file descriptor backing packetFlow (WireGuard-style):
    // scan low fds for the one whose UTUN_OPT_IFNAME getsockopt succeeds and
    // returns a "utun*" name. (No ctl_info needed — that was leftover from a
    // different approach and doesn't import cleanly on iOS anyway.)
    private var tunnelFileDescriptor: Int32 {
        for fd: Int32 in 0...1024 {
            var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            var len = socklen_t(name.count)
            let ret = getsockopt(fd, 2 /* SYSPROTO_CONTROL */,
                                 2 /* UTUN_OPT_IFNAME */, &name, &len)
            if ret == 0 && String(cString: name).hasPrefix("utun") {
                return fd
            }
        }
        return -1
    }
}
