package fingerprint

import (
	"sync"
	"time"
)

// JA4Store provides thread-safe storage for JA4 fingerprints
// keyed by connection remote address
type JA4Store struct {
	mu   sync.RWMutex
	data map[string]*storedFingerprint
	ttl  time.Duration
	done chan struct{}
}

type storedFingerprint struct {
	fingerprint *JA4Fingerprint
	timestamp   time.Time
}

// NewJA4Store creates a new JA4 store with TTL-based cleanup
// ttl: duration after which fingerprints are removed
func NewJA4Store(ttl time.Duration) *JA4Store {
	store := &JA4Store{
		data: make(map[string]*storedFingerprint),
		ttl:  ttl,
		done: make(chan struct{}),
	}
	go store.cleanup()
	return store
}

// Set stores a fingerprint for a given remote address
func (s *JA4Store) Set(remoteAddr string, fp *JA4Fingerprint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[remoteAddr] = &storedFingerprint{
		fingerprint: fp,
		timestamp:   time.Now(),
	}
}

// Get retrieves a fingerprint for a given remote address
// Returns nil if not found or expired
func (s *JA4Store) Get(remoteAddr string) *JA4Fingerprint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored, ok := s.data[remoteAddr]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Since(stored.timestamp) > s.ttl {
		return nil
	}

	return stored.fingerprint
}

// cleanup periodically removes expired entries
func (s *JA4Store) cleanup() {
	ticker := time.NewTicker(s.ttl / 2) // Run cleanup at half TTL interval
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.removeExpired()
		case <-s.done:
			return
		}
	}
}

func (s *JA4Store) removeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for addr, stored := range s.data {
		if now.Sub(stored.timestamp) > s.ttl {
			delete(s.data, addr)
		}
	}
}

// Close stops the cleanup goroutine
func (s *JA4Store) Close() {
	close(s.done)
}

// Stats returns statistics about the store (for monitoring)
func (s *JA4Store) Stats() (count int, oldest time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count = len(s.data)
	now := time.Now()
	var oldestTime time.Time

	for _, stored := range s.data {
		if oldestTime.IsZero() || stored.timestamp.Before(oldestTime) {
			oldestTime = stored.timestamp
		}
	}

	if !oldestTime.IsZero() {
		oldest = now.Sub(oldestTime)
	}

	return count, oldest
}
