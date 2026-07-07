package main

import (
	"net"
	"sync"
	"time"
)

type IPLearning struct {
	mu sync.RWMutex
	m  map[string]*entry
}

type entry struct {
	addr *net.UDPAddr
	seen time.Time
}

const ipLearnEvictInterval = 5 * time.Minute
const ipLearnStaleTimeout = 5 * time.Minute

func NewIPLearningTable() *IPLearning {
	t := &IPLearning{m: map[string]*entry{}}
	go t.evictLoop()
	return t
}

func (t *IPLearning) evictLoop() {
	ticker := time.NewTicker(ipLearnEvictInterval)
	defer ticker.Stop()
	for range ticker.C {
		t.mu.Lock()
		now := time.Now()
		for ip, e := range t.m {
			if now.Sub(e.seen) > ipLearnStaleTimeout {
				delete(t.m, ip)
			}
		}
		t.mu.Unlock()
	}
}

func (t *IPLearning) Learn(ip string, addr *net.UDPAddr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[ip] = &entry{addr: addr, seen: time.Now()}
}

// ForgetAddr removes every overlay-IP mapping that points at addr. Called
// when a session to addr is evicted or when a send-path lookup discovers the
// mapping is stale — routing to an endpoint with no live session silently
// blackholes traffic even after a fresh session exists elsewhere.
func (t *IPLearning) ForgetAddr(addr *net.UDPAddr) {
	key := addr.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, e := range t.m {
		if e.addr.String() == key {
			delete(t.m, ip)
		}
	}
}

func (t *IPLearning) Lookup(ip string) *net.UDPAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if e, ok := t.m[ip]; ok {
		return e.addr
	}
	return nil
}
