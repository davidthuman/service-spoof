package fingerprint

import (
	"sync"
	"testing"
	"time"
)

func TestJA4Store_SetGet(t *testing.T) {
	store := NewJA4Store(1 * time.Minute)
	defer store.Close()

	fp := &JA4Fingerprint{
		Raw:         "t13d0305h2_abc123_def456",
		TLSVersion:  "13",
		CipherCount: 3,
	}

	// Set fingerprint
	store.Set("192.168.1.1:12345", fp)

	// Get fingerprint
	result := store.Get("192.168.1.1:12345")
	if result == nil {
		t.Fatal("Get() returned nil for existing fingerprint")
	}

	if result.Raw != fp.Raw {
		t.Errorf("Get() Raw = %s, want %s", result.Raw, fp.Raw)
	}
}

func TestJA4Store_GetNonExistent(t *testing.T) {
	store := NewJA4Store(1 * time.Minute)
	defer store.Close()

	result := store.Get("192.168.1.1:99999")
	if result != nil {
		t.Errorf("Get() for non-existent key returned %v, want nil", result)
	}
}

func TestJA4Store_Expiration(t *testing.T) {
	ttl := 100 * time.Millisecond
	store := NewJA4Store(ttl)
	defer store.Close()

	fp := &JA4Fingerprint{
		Raw: "test_fingerprint",
	}

	store.Set("192.168.1.1:12345", fp)

	// Should exist immediately
	result := store.Get("192.168.1.1:12345")
	if result == nil {
		t.Fatal("Get() returned nil immediately after Set()")
	}

	// Wait for expiration
	time.Sleep(ttl + 50*time.Millisecond)

	// Should be expired
	result = store.Get("192.168.1.1:12345")
	if result != nil {
		t.Errorf("Get() returned %v after expiration, want nil", result)
	}
}

func TestJA4Store_Cleanup(t *testing.T) {
	ttl := 100 * time.Millisecond
	store := NewJA4Store(ttl)
	defer store.Close()

	// Add multiple entries
	for i := 0; i < 10; i++ {
		fp := &JA4Fingerprint{Raw: "test"}
		store.Set("192.168.1."+string(rune('0'+i))+":12345", fp)
	}

	// Check count
	count, _ := store.Stats()
	if count != 10 {
		t.Errorf("Stats() count = %d, want 10", count)
	}

	// Wait for cleanup to run (TTL/2 + buffer)
	time.Sleep(ttl + 100*time.Millisecond)

	// Entries should be cleaned up
	count, _ = store.Stats()
	if count != 0 {
		t.Errorf("Stats() count after cleanup = %d, want 0", count)
	}
}

func TestJA4Store_Concurrent(t *testing.T) {
	store := NewJA4Store(1 * time.Minute)
	defer store.Close()

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			fp := &JA4Fingerprint{Raw: "test"}
			store.Set("192.168.1.1:"+string(rune(id)), fp)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_ = store.Get("192.168.1.1:" + string(rune(id)))
		}(i)
	}

	wg.Wait()

	// Verify some entries exist
	count, _ := store.Stats()
	if count == 0 {
		t.Error("Stats() count = 0 after concurrent operations, expected > 0")
	}
}

func TestJA4Store_Stats(t *testing.T) {
	store := NewJA4Store(1 * time.Minute)
	defer store.Close()

	// Empty store
	count, oldest := store.Stats()
	if count != 0 {
		t.Errorf("Stats() empty store count = %d, want 0", count)
	}
	if oldest != 0 {
		t.Errorf("Stats() empty store oldest = %v, want 0", oldest)
	}

	// Add entries
	fp1 := &JA4Fingerprint{Raw: "test1"}
	store.Set("addr1", fp1)

	time.Sleep(10 * time.Millisecond)

	fp2 := &JA4Fingerprint{Raw: "test2"}
	store.Set("addr2", fp2)

	count, oldest = store.Stats()
	if count != 2 {
		t.Errorf("Stats() count = %d, want 2", count)
	}
	if oldest < 10*time.Millisecond {
		t.Errorf("Stats() oldest = %v, want >= 10ms", oldest)
	}
}

func TestJA4Store_Close(t *testing.T) {
	store := NewJA4Store(1 * time.Minute)

	// Add some data
	fp := &JA4Fingerprint{Raw: "test"}
	store.Set("addr1", fp)

	// Close should not panic
	store.Close()

	// Operations after close should still work (map access is still valid)
	// Only the cleanup goroutine is stopped
	result := store.Get("addr1")
	if result == nil {
		t.Error("Get() after Close() returned nil, want valid fingerprint")
	}
}

func TestJA4Store_OverwriteEntry(t *testing.T) {
	store := NewJA4Store(1 * time.Minute)
	defer store.Close()

	addr := "192.168.1.1:12345"

	// Set first fingerprint
	fp1 := &JA4Fingerprint{Raw: "fingerprint1"}
	store.Set(addr, fp1)

	// Overwrite with second fingerprint
	fp2 := &JA4Fingerprint{Raw: "fingerprint2"}
	store.Set(addr, fp2)

	// Should get the latest
	result := store.Get(addr)
	if result == nil {
		t.Fatal("Get() returned nil")
	}
	if result.Raw != "fingerprint2" {
		t.Errorf("Get() Raw = %s, want fingerprint2", result.Raw)
	}
}
