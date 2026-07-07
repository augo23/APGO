package main

// Minimal bencode decoder — just enough to parse BitTorrent HTTP tracker
// announce responses (BEP 3). Public trackers return bencoded dictionaries,
// not JSON; the previous JSON decoder failed on every real-world HTTP
// tracker in trackers.txt.
//
// Supported values: integers (i...e), byte strings (<len>:<bytes>),
// lists (l...e), dicts (d...e). Decoded as int64, string, []interface{},
// map[string]interface{} respectively.

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

func bdecode(data []byte) (interface{}, error) {
	v, rest, err := bdecodeValue(data)
	if err != nil {
		return nil, err
	}
	_ = rest // trailing bytes tolerated
	return v, nil
}

func bdecodeValue(data []byte) (interface{}, []byte, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("bencode: unexpected end of data")
	}
	switch {
	case data[0] == 'i':
		end := indexByte(data, 'e')
		if end < 0 {
			return nil, nil, errors.New("bencode: unterminated integer")
		}
		n, err := strconv.ParseInt(string(data[1:end]), 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("bencode: bad integer: %w", err)
		}
		return n, data[end+1:], nil

	case data[0] >= '0' && data[0] <= '9':
		colon := indexByte(data, ':')
		if colon < 0 {
			return nil, nil, errors.New("bencode: unterminated string length")
		}
		slen, err := strconv.Atoi(string(data[:colon]))
		if err != nil || slen < 0 {
			return nil, nil, errors.New("bencode: bad string length")
		}
		if colon+1+slen > len(data) {
			return nil, nil, errors.New("bencode: string exceeds data")
		}
		return string(data[colon+1 : colon+1+slen]), data[colon+1+slen:], nil

	case data[0] == 'l':
		rest := data[1:]
		var list []interface{}
		for {
			if len(rest) == 0 {
				return nil, nil, errors.New("bencode: unterminated list")
			}
			if rest[0] == 'e' {
				return list, rest[1:], nil
			}
			var v interface{}
			var err error
			v, rest, err = bdecodeValue(rest)
			if err != nil {
				return nil, nil, err
			}
			list = append(list, v)
		}

	case data[0] == 'd':
		rest := data[1:]
		dict := map[string]interface{}{}
		for {
			if len(rest) == 0 {
				return nil, nil, errors.New("bencode: unterminated dict")
			}
			if rest[0] == 'e' {
				return dict, rest[1:], nil
			}
			var k, v interface{}
			var err error
			k, rest, err = bdecodeValue(rest)
			if err != nil {
				return nil, nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, nil, errors.New("bencode: dict key is not a string")
			}
			v, rest, err = bdecodeValue(rest)
			if err != nil {
				return nil, nil, err
			}
			dict[key] = v
		}

	default:
		return nil, nil, fmt.Errorf("bencode: unexpected byte %q", data[0])
	}
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// parseTrackerBencode converts a bencoded HTTP tracker announce response
// into a TrackerResponse. Handles both compact peers (a packed byte string
// of 6-byte IPv4:port entries) and the dictionary-model peer list.
func parseTrackerBencode(body []byte) (TrackerResponse, error) {
	v, err := bdecode(body)
	if err != nil {
		return TrackerResponse{}, err
	}
	dict, ok := v.(map[string]interface{})
	if !ok {
		return TrackerResponse{}, errors.New("tracker response is not a dict")
	}

	if reason, ok := dict["failure reason"].(string); ok {
		return TrackerResponse{}, fmt.Errorf("tracker failure: %s", reason)
	}

	var tr TrackerResponse
	if iv, ok := dict["interval"].(int64); ok {
		tr.Interval = int(iv)
	}

	switch peers := dict["peers"].(type) {
	case string:
		// Compact model: 6 bytes per peer.
		tr.Peers = parseCompactPeers([]byte(peers))
	case []interface{}:
		// Dictionary model: list of dicts with "ip" and "port".
		for _, p := range peers {
			pd, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			ip, _ := pd["ip"].(string)
			port, _ := pd["port"].(int64)
			if ip == "" || port <= 0 || port >= 65536 {
				continue
			}
			tr.Peers = append(tr.Peers, net.JoinHostPort(ip, strconv.FormatInt(port, 10)))
		}
	}
	return tr, nil
}
