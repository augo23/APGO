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
func (t *IPLearning) Lookup(ip string) *net.UDPAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if e, ok := t.m[ip]; ok {
		return e.addr
	}
	return nil
}
