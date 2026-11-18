package main

// fullvpn.go applies Full VPN (use_exit / exit_peer) to the RUNNING client.
//
// Settings used to only write the config file and say "reconnect to apply" —
// but Connect is a no-op while the client runs, so turning Full VPN on did
// nothing and traffic kept leaving through the home connection. The client
// now switches full-VPN mode live (client/fulltunnel.go); this pushes the
// saved choice to it.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// applyFullVPNLive pushes the Full VPN setting to the running client. It
// returns a short message for the user ("" when nothing needed saying).
func applyFullVPNLive(on bool, peer string) string {
	body, _ := json.Marshal(map[string]any{"use_exit": on, "exit_peer": peer})
	code, resp, err := ctlDo("POST", "/api/use-exit", body)
	switch {
	case err != nil:
		return "" // not connected: applies on the next Connect
	case code == http.StatusNotFound:
		return "The running client is an older build that can't switch Full VPN live — Disconnect and Connect to apply it."
	case code != http.StatusOK:
		return "Full VPN could not be applied: " + strings.TrimSpace(string(resp))
	case on:
		if peer != "" {
			return fmt.Sprintf("Full VPN on — internet traffic now goes through %s.", peer)
		}
		return "Full VPN on — internet traffic now goes through the fastest exit node."
	default:
		return "Full VPN off — internet traffic uses this computer's own connection."
	}
}

// fullVPNDiffers reports whether the running client's full-VPN state differs
// from the saved choice. When the client can't be asked, it falls back to
// whether the saved choice changed.
func fullVPNDiffers(on bool, peer string, prevOn bool, prevPeer string) bool {
	code, resp, err := ctlDo("GET", "/api/exits", nil)
	if err != nil || code != http.StatusOK {
		return on != prevOn || peer != prevPeer
	}
	var st struct {
		UseExit bool   `json:"use_exit"`
		Pin     string `json:"pin"`
	}
	if json.Unmarshal(resp, &st) != nil {
		return on != prevOn || peer != prevPeer
	}
	return st.UseExit != on || (on && st.Pin != strings.TrimSpace(peer))
}

// exitNodeDiffers reports whether the running client's exit-node mode differs
// from the saved choice (falling back to whether the choice changed).
func exitNodeDiffers(on, prevOn bool) bool {
	code, resp, err := ctlDo("GET", "/api/info", nil)
	if err != nil || code != http.StatusOK {
		return on != prevOn
	}
	var st struct {
		ExitNode *bool `json:"exit_node"`
	}
	if json.Unmarshal(resp, &st) != nil || st.ExitNode == nil {
		return on != prevOn
	}
	return *st.ExitNode != on
}

// applyExitNodeLive pushes the "be an exit node" setting to the running
// client. Like Full VPN, it used to wait for a reconnect that Connect never
// performed, so other devices never saw this computer as an exit.
func applyExitNodeLive(on bool) string {
	body, _ := json.Marshal(map[string]any{"exit_node": on})
	code, resp, err := ctlDo("POST", "/api/exit-node", body)
	switch {
	case err != nil:
		return ""
	case code == http.StatusNotFound:
		return "The running client is an older build that can't switch internal exit node mode live — Disconnect and Connect to apply it."
	case code != http.StatusOK:
		return "This computer could not become an internal exit node: " + strings.TrimSpace(string(resp))
	case on:
		return "This computer is now an internal exit node — devices on your network can route their internet traffic through it."
	default:
		return "This computer is no longer an internal exit node."
	}
}

// handlePanelNetworkSet persists exit changes made on the MAIN network's row
// of the dashboard network list (the desktop app owns that config file), then
// hands the request to the client, which applies them live.
func handlePanelNetworkSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	var req struct {
		NetworkName string  `json:"network_name"`
		UseExit     *bool   `json:"use_exit"`
		ExitPeer    *string `json:"exit_peer"`
		ExitNode    *bool   `json:"exit_node"`
	}
	if json.Unmarshal(body, &req) == nil && (req.UseExit != nil || req.ExitPeer != nil || req.ExitNode != nil) {
		if c := loadConfig(); c.NetworkName != "" && c.NetworkName == req.NetworkName {
			if req.UseExit != nil {
				c.UseExit = *req.UseExit
			}
			if req.ExitPeer != nil {
				c.ExitPeer = strings.TrimSpace(*req.ExitPeer)
			}
			if req.ExitNode != nil {
				c.ExitNode = *req.ExitNode
			}
			if err := saveConfig(c); err != nil {
				http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
				return
			}
			registerCurrentProfileUI()
		}
	}
	proxyCtl(w, "POST", "/api/network-set", body)
}

// usePublicDiffers reports whether the running client's "use public exit
// nodes" setting differs from on.
func usePublicDiffers(on bool) bool {
	code, resp, err := ctlDo("GET", "/api/exits", nil)
	if err != nil || code != http.StatusOK {
		return false
	}
	var st struct {
		UsePublic *bool `json:"use_public_exits"`
	}
	if json.Unmarshal(resp, &st) != nil || st.UsePublic == nil {
		return false
	}
	return *st.UsePublic != on
}

func applyUsePublicExitsLive(on bool) string {
	body, _ := json.Marshal(map[string]any{"use_public_exits": on})
	code, resp, err := ctlDo("POST", "/api/use-public-exits", body)
	switch {
	case err != nil:
		return ""
	case code == http.StatusNotFound:
		return "The running client is an older build — Disconnect and Connect to apply the public exit setting."
	case code != http.StatusOK:
		return "Could not change the public exit setting: " + strings.TrimSpace(string(resp))
	case on:
		return "Public exit nodes will be used when no internal exit is reachable."
	default:
		return "Public exit nodes will no longer be used."
	}
}

// publicExitDiffers reports whether the running client's public-exit state
// differs from on.
func publicExitDiffers(on bool) bool {
	code, resp, err := ctlDo("GET", "/api/public-exit", nil)
	if err != nil || code != http.StatusOK {
		return false
	}
	var st struct {
		Enabled bool `json:"enabled"`
	}
	if json.Unmarshal(resp, &st) != nil {
		return false
	}
	return st.Enabled != on
}

// applyPublicExitLive pushes the public exit node setting and its limits to
// the running client.
func applyPublicExitLive(c mConfig) string {
	req := map[string]any{
		"enabled":    c.PublicExit,
		"up":         c.PublicExitUpLimit,
		"down":       c.PublicExitDownLimit,
		"quota":      c.PublicExitQuota,
		"per_client": c.PublicExitPerClientLimit,
	}
	if c.PublicExitMaxClients > 0 {
		req["max_clients"] = c.PublicExitMaxClients
	}
	body, _ := json.Marshal(req)
	code, resp, err := ctlDo("POST", "/api/public-exit", body)
	msg := strings.TrimSpace(string(resp))
	switch {
	case err != nil:
		return ""
	case code == http.StatusNotFound:
		return "The running client is an older build — Disconnect and Connect to apply the public exit node setting."
	case code != http.StatusOK && c.PublicExit && strings.Contains(msg, "must also have"):
		return "The public exit node will start after Disconnect and Connect (it needs the DHT and public relay, which apply on reconnect)."
	case code != http.StatusOK:
		return "This computer could not become a public exit node: " + msg
	case c.PublicExit:
		return "This computer is now a public exit node — any APGO user can use its internet connection, within your limits."
	default:
		return "This computer is no longer a public exit node."
	}
}

// handlePanelFullVPN backs the Full VPN panel on the dashboard's main page.
//
//	GET  -> {"use_exit", "exit_peer", "use_public_exits", "connected", "live"}
//	        where "live" is the running client's /api/exits answer (the exit
//	        list with latency, reachability and which one carries traffic),
//	        or null while disconnected.
//	POST {"use_exit"?, "exit_peer"?, "use_public_exits"?} -> {"ok", "note"}
//	        saves the choice to this computer's config (so it survives a
//	        restart) and applies it to the running client at once.
//
// exit_peer is "" for the fastest exit, a node (key fingerprint, overlay IP
// or name) to pin, or "public" for public exit nodes only. The panel pins by
// key fingerprint: an overlay IP can be reassigned to a different node, a
// key cannot.
func handlePanelFullVPN(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := loadConfig()
		out := map[string]any{
			"use_exit":         c.UseExit,
			"exit_peer":        c.ExitPeer,
			"use_public_exits": c.UsePublicExits,
			"connected":        false,
			"live":             nil,
		}
		if code, resp, err := ctlDo("GET", "/api/exits", nil); err == nil && code == http.StatusOK {
			var live map[string]any
			if json.Unmarshal(resp, &live) == nil {
				out["connected"] = true
				out["live"] = live
			}
		}
		writeJSON(w, out)
	case http.MethodPost:
		if r.Header.Get("X-Requested-With") == "" {
			http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
			return
		}
		var req struct {
			UseExit        *bool   `json:"use_exit"`
			ExitPeer       *string `json:"exit_peer"`
			UsePublicExits *bool   `json:"use_public_exits"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		if json.Unmarshal(body, &req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		c := loadConfig()
		if c.NetworkName == "" {
			http.Error(w, "set up a network in Settings first", http.StatusBadRequest)
			return
		}
		prevOn, prevPeer, prevPub := c.UseExit, c.ExitPeer, c.UsePublicExits
		if req.UseExit != nil {
			c.UseExit = *req.UseExit
		}
		if req.ExitPeer != nil {
			p := strings.TrimSpace(*req.ExitPeer)
			if len(p) > 128 || strings.ContainsAny(p, "\r\n\x00") {
				http.Error(w, "invalid exit node", http.StatusBadRequest)
				return
			}
			c.ExitPeer = p
		}
		if req.UsePublicExits != nil {
			c.UsePublicExits = *req.UsePublicExits
		}
		if err := saveConfig(c); err != nil {
			http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
			return
		}
		registerCurrentProfileUI()

		var notes []string
		// Public-exit permission first: turning Full VPN on with "public only"
		// must not start before the client is allowed to use public exits.
		if c.UsePublicExits != prevPub || usePublicDiffers(c.UsePublicExits) {
			if n := applyUsePublicExitsLive(c.UsePublicExits); n != "" {
				notes = append(notes, n)
			}
		}
		if fullVPNDiffers(c.UseExit, c.ExitPeer, prevOn, prevPeer) {
			if n := applyFullVPNLive(c.UseExit, c.ExitPeer); n != "" {
				notes = append(notes, n)
			}
		}
		if c.UseExit && (c.ExitNode || c.PublicExit) {
			notes = append(notes, "While Full VPN is on, this computer can't reliably be an exit for other devices.")
		}
		writeJSON(w, map[string]any{"ok": true, "note": strings.Join(notes, " ")})
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
}
