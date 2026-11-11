package overlaymobile

// resetAdminTrustState forgets every piece of in-memory admin trust left over
// from a previous run in this process.
//
// On iOS and Android the Go core lives inside a long-lived process (the
// network extension / VpnService) that can be Start()ed again for a DIFFERENT
// network profile. Package globals survive that, so without this the new run
// kept trusting the previous network's admin key and kept the approvals,
// revocations and provisions it had verified — letting the old network's admin
// sign control records the new network would accept. Everything cleared here
// is re-loaded from the new profile's own env/files by run().
func resetAdminTrustState() {
	adminPub = nil
	adminPubParsed = nil

	sealedMu.Lock()
	sealedBlob = nil
	sealedEpoch = 0
	sealedSigned = false
	sealedKeyFile = ""
	sealedMu.Unlock()

	approvals.mu.Lock()
	approvals.recs = map[[32]byte]storedApproval{}
	approvals.path = ""
	approvals.mu.Unlock()

	revocations.mu.Lock()
	revocations.recs = map[[32]byte]storedRev{}
	revocations.path = ""
	revocations.mu.Unlock()

	provisions.mu.Lock()
	provisions.recs = map[[32]byte]SignedProvision{}
	provisions.addrSeq = map[string]int64{}
	provisions.path = ""
	provisions.mu.Unlock()
}
