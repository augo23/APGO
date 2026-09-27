package overlaymobile

// provstore.go — the store of admin-signed provisions (address / name
// assignments), shared verbatim by the desktop client and the mobile core.
//
// ONE ADDRESS, ONE KEY: THE NEWEST ASSIGNMENT WINS, PERMANENTLY
//
// A provision binds an overlay address to a node KEY, and the store is keyed
// by key. When a machine is reinstalled it gets a new key; the admin assigns
// the old address to the new key; the old key's record is now stale. Stale
// records used to come back forever: every node regossips its whole store,
// and a node accepted any record that was newer than what it held FOR THAT
// KEY — so an old key's record, retired on one node, was simply re-learned
// from the next node that still had it (mobile nodes never retired anything).
// The visible symptom was a permanent "DUPLICATE CLAIM" warning and peers
// resolving the address to a machine that no longer exists.
//
// The store now keeps a small ledger: for every overlay address, the highest
// provision sequence ever seen for it, whichever key it named. A record whose
// address has already been assigned by a NEWER signature is refused, and when
// a newer record for an address arrives, every older record for that address
// is dropped. The ledger is persisted next to the store, so a retired record
// stays retired across restarts even after the winning key has itself moved
// on to another address. Sequences are the admin's signing timestamps, so
// "newest" is the operator's latest decision.

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
)

type provStore struct {
	mu   sync.Mutex
	recs map[[32]byte]SignedProvision
	path string
	// addrSeq: overlay address -> highest provision seq ever seen for it.
	addrSeq map[string]int64
}

var provisions = &provStore{recs: map[[32]byte]SignedProvision{}, addrSeq: map[string]int64{}}

func provAddrIP(rec SignedProvision) string {
	if rec.Address == "" {
		return ""
	}
	return stripMask(normalizeOverlayAddr(rec.Address))
}

// putLocked applies the store rules to one verified record. It returns
// whether the record was stored and which other keys' records it retired.
// Caller holds s.mu.
func (s *provStore) putLocked(pub [32]byte, rec SignedProvision) (bool, []string) {
	if s.recs == nil {
		s.recs = map[[32]byte]SignedProvision{}
	}
	if s.addrSeq == nil {
		s.addrSeq = map[string]int64{}
	}
	if cur, ok := s.recs[pub]; ok && rec.Seq <= cur.Seq {
		return false, nil
	}
	ip := provAddrIP(rec)
	if ip != "" {
		if best, ok := s.addrSeq[ip]; ok && rec.Seq < best {
			// This address was assigned again later (to this or another
			// key). The record is a leftover; do not let it back in.
			return false, nil
		}
		for k, other := range s.recs {
			if k != pub && provAddrIP(other) == ip && other.Seq > rec.Seq {
				return false, nil
			}
		}
	}
	s.recs[pub] = rec
	var retired []string
	if ip != "" {
		if rec.Seq > s.addrSeq[ip] {
			s.addrSeq[ip] = rec.Seq
		}
		for k, other := range s.recs {
			if k != pub && provAddrIP(other) == ip && other.Seq < rec.Seq {
				delete(s.recs, k)
				retired = append(retired, peerKeyFingerprint(k[:]))
			}
		}
	}
	return true, retired
}

// put stores rec if it is the newest word on both its key and its address.
func (s *provStore) put(pub [32]byte, rec SignedProvision) bool {
	s.mu.Lock()
	ok, retired := s.putLocked(pub, rec)
	s.mu.Unlock()
	if !ok {
		return false
	}
	if len(retired) > 0 {
		log.Printf("[provision] %s assigned to %s — retired %d older claim(s) on it: %s",
			provAddrIP(rec), peerKeyFingerprint(pub[:]), len(retired), strings.Join(retired, ", "))
	}
	s.save()
	return true
}

// ownsAddress reports whether ip is currently assigned to pub by the newest
// provision for it.
func (s *provStore) ownsAddress(pub [32]byte, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[pub]
	return ok && provAddrIP(rec) == ip && rec.Seq >= s.addrSeq[ip]
}

func (s *provStore) get(pub [32]byte) (SignedProvision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[pub]
	return r, ok
}

func (s *provStore) list() []SignedProvision {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SignedProvision, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, r)
	}
	return out
}

func writeFileAtomic(path string, data []byte) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		_ = os.Rename(tmp, path)
	}
}

func (s *provStore) ledgerPath() string {
	if s.path == "" {
		return ""
	}
	return s.path + ".addrseq.json"
}

func (s *provStore) save() {
	s.mu.Lock()
	path, lpath := s.path, s.ledgerPath()
	list := make([]SignedProvision, 0, len(s.recs))
	for _, r := range s.recs {
		list = append(list, r)
	}
	ledger := make(map[string]int64, len(s.addrSeq))
	for k, v := range s.addrSeq {
		ledger[k] = v
	}
	s.mu.Unlock()
	if path == "" {
		return
	}
	if data, err := json.MarshalIndent(list, "", "  "); err == nil {
		writeFileAtomic(path, data)
	}
	if data, err := json.Marshal(ledger); err == nil {
		writeFileAtomic(lpath, data)
	}
}

// load reads persisted provisions (re-verifying each against the admin key)
// and the address ledger, then applies the store rules to everything loaded,
// oldest first, so a store poisoned by earlier builds repairs itself.
func (s *provStore) load(path string) {
	s.mu.Lock()
	s.path = path
	if s.addrSeq == nil {
		s.addrSeq = map[string]int64{}
	}
	if data, err := os.ReadFile(s.ledgerPath()); err == nil {
		var ledger map[string]int64
		if json.Unmarshal(data, &ledger) == nil {
			for k, v := range ledger {
				if v > s.addrSeq[k] {
					s.addrSeq[k] = v
				}
			}
		}
	}
	s.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var list []SignedProvision
	if json.Unmarshal(data, &list) != nil {
		return
	}
	type verified struct {
		pub [32]byte
		rec SignedProvision
	}
	var good []verified
	for _, rec := range list {
		if pub, ok := verifyProvision(rec); ok {
			good = append(good, verified{pub, rec})
		}
	}
	// Oldest first: each record then meets only the ones it may supersede.
	for i := 1; i < len(good); i++ {
		for j := i; j > 0 && good[j].rec.Seq < good[j-1].rec.Seq; j-- {
			good[j], good[j-1] = good[j-1], good[j]
		}
	}
	var dropped []string
	s.mu.Lock()
	for _, g := range good {
		if ok, retired := s.putLocked(g.pub, g.rec); ok {
			for _, fp := range retired {
				dropped = append(dropped, provAddrIP(g.rec)+" from "+fp)
			}
		} else if ip := provAddrIP(g.rec); ip != "" {
			if cur, exists := s.recs[g.pub]; !exists || cur.Seq < g.rec.Seq {
				dropped = append(dropped, ip+" from "+peerKeyFingerprint(g.pub[:]))
			}
		}
	}
	names := make(map[[32]byte]string)
	for pub, rec := range s.recs {
		if rec.Name != "" {
			names[pub] = rec.Name
		}
	}
	s.mu.Unlock()
	for pub, name := range names {
		setPeerName(pub, name)
	}
	if len(dropped) > 0 {
		log.Printf("[provision] dropped %d superseded address claim(s) left behind by earlier installs: %s. "+
			"Each address now belongs to the key it was most recently assigned to.",
			len(dropped), strings.Join(dropped, ", "))
	}
	s.save()
}

// pruneSupersededAddresses re-applies the store rules to the current contents.
// Kept for callers of the previous API; load() already does this.
func (s *provStore) pruneSupersededAddresses() {
	s.mu.Lock()
	type kv struct {
		pub [32]byte
		rec SignedProvision
	}
	all := make([]kv, 0, len(s.recs))
	for k, v := range s.recs {
		all = append(all, kv{k, v})
	}
	s.recs = map[[32]byte]SignedProvision{}
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].rec.Seq < all[j-1].rec.Seq; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	for _, e := range all {
		s.putLocked(e.pub, e.rec)
	}
	s.mu.Unlock()
}
