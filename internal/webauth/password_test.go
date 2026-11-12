// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package webauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestPHCRoundTripAndParameters(t *testing.T) {
	h := NewHasher()
	phc, err := h.Hash(context.Background(), "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("encoded parameters are not the constants: %s", phc)
	}
	ok, rehash, err := h.Verify(context.Background(), "correct horse battery", phc)
	if err != nil || !ok || rehash {
		t.Fatalf("right password: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, _, err = h.Verify(context.Background(), "correct horse batterz", phc)
	if err != nil || ok {
		t.Fatalf("wrong password: ok=%v err=%v", ok, err)
	}
	// Two hashes of one password differ (random salt).
	phc2, _ := h.Hash(context.Background(), "correct horse battery")
	if phc == phc2 {
		t.Fatal("two hashes of one password are identical: the salt is not random")
	}
}

func TestNeedsRehashForOlderParameters(t *testing.T) {
	h := NewHasher()
	salt := make([]byte, 16)
	key := argon2.IDKey([]byte("old parameters pw"), salt, 1, 8192, 1, 32)
	old := encodePHC(8192, 1, 1, salt, key)
	ok, rehash, err := h.Verify(context.Background(), "old parameters pw", old)
	if err != nil || !ok || !rehash {
		t.Fatalf("old-parameter hash: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
}

func TestMalformedAndOutOfBoundsHashesRejectedWithoutDeriving(t *testing.T) {
	var calls atomic.Int32
	h := newHasher(func(p, s []byte, tt, m uint32, th uint8, k uint32) []byte {
		calls.Add(1)
		return make([]byte, k)
	})
	salt := "AAAAAAAAAAAAAAAAAAAAAA"
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for name, s := range map[string]string{
		"empty":         "",
		"bcrypt":        "$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		"argon2i":       "$argon2i$v=19$m=19456,t=2,p=1$" + salt + "$" + key,
		"old version":   "$argon2id$v=16$m=19456,t=2,p=1$" + salt + "$" + key,
		"huge memory":   "$argon2id$v=19$m=4194304,t=2,p=1$" + salt + "$" + key,
		"huge time":     "$argon2id$v=19$m=19456,t=11,p=1$" + salt + "$" + key,
		"huge threads":  "$argon2id$v=19$m=19456,t=2,p=17$" + salt + "$" + key,
		"zero time":     "$argon2id$v=19$m=19456,t=0,p=1$" + salt + "$" + key,
		"overflow":      "$argon2id$v=19$m=99999999999,t=2,p=1$" + salt + "$" + key,
		"long salt":     "$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("A", 200) + "$" + key,
		"long key":      "$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$" + strings.Repeat("A", 200),
		"padded base64": "$argon2id$v=19$m=19456,t=2,p=1$" + salt + "==$" + key,
		"missing part":  "$argon2id$v=19$m=19456,t=2,p=1$" + salt,
		"wrong order":   "$argon2id$v=19$t=2,m=19456,p=1$" + salt + "$" + key,
		"short salt":    "$argon2id$v=19$m=19456,t=2,p=1$AAAA$" + key,
	} {
		_, _, err := h.Verify(context.Background(), "x", s)
		if !errors.Is(err, ErrBadHash) {
			t.Errorf("%s: err=%v, want ErrBadHash", name, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("%d key derivations for malformed hashes, want 0", calls.Load())
	}
}

func TestCheckPolicy(t *testing.T) {
	cases := []struct {
		pw string
		ok bool
	}{
		{strings.Repeat("a", 14), false},
		{strings.Repeat("a", 15), true},
		{strings.Repeat("a", 256), true},
		{strings.Repeat("a", 257), false},
		{"pässword-with-ümlauts", true},
		{"nul\x00in-the-middle-pw", false},
		{"invalid-utf8-\xff\xfe-pw!", false},
	}
	for _, c := range cases {
		err := CheckPolicy(c.pw)
		if (err == nil) != c.ok {
			t.Errorf("CheckPolicy(%d bytes %q) = %v, want ok=%v", len(c.pw), c.pw, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrPolicy) {
			t.Errorf("error does not wrap ErrPolicy: %v", err)
		}
	}
	pw, err := GeneratePassword()
	if err != nil || len(pw) != 24 || CheckPolicy(pw) != nil {
		t.Fatalf("generated password %q: %v", pw, err)
	}
}

// blockingDerive blocks every derivation until released and records how many
// ran at once.
type blockingDerive struct {
	mu          sync.Mutex
	running     int
	maxRunning  int
	started     chan struct{}
	release     chan struct{}
	totalCalled atomic.Int32
}

func newBlocking() *blockingDerive {
	return &blockingDerive{started: make(chan struct{}, 64), release: make(chan struct{})}
}

func (b *blockingDerive) fn(p, s []byte, t, m uint32, th uint8, k uint32) []byte {
	b.totalCalled.Add(1)
	b.mu.Lock()
	b.running++
	b.maxRunning = max(b.maxRunning, b.running)
	b.mu.Unlock()
	b.started <- struct{}{}
	<-b.release
	b.mu.Lock()
	b.running--
	b.mu.Unlock()
	return make([]byte, k)
}

func TestHashSemaphoreCapsConcurrency(t *testing.T) {
	b := newBlocking()
	h := newHasher(b.fn)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.Hash(context.Background(), "pw")
		}()
	}
	for i := 0; i < MaxConcurrentHashes; i++ {
		<-b.started
	}
	// Give any fifth hash the chance to (wrongly) start.
	time.Sleep(100 * time.Millisecond)
	b.mu.Lock()
	running := b.running
	b.mu.Unlock()
	if running != MaxConcurrentHashes {
		t.Fatalf("%d hashes running at once, want exactly %d", running, MaxConcurrentHashes)
	}
	close(b.release)
	wg.Wait()
	if b.maxRunning > MaxConcurrentHashes {
		t.Fatalf("saw %d concurrent hashes, cap is %d", b.maxRunning, MaxConcurrentHashes)
	}
	if got := b.totalCalled.Load(); got != 12 {
		t.Fatalf("%d derivations, want 12", got)
	}
}

func TestWaiterRespectsContext(t *testing.T) {
	b := newBlocking()
	h := newHasher(b.fn)
	for i := 0; i < MaxConcurrentHashes; i++ {
		go func() { _, _ = h.Hash(context.Background(), "pw") }()
		<-b.started
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := h.Hash(ctx, "pw"); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a waiter ignored its cancelled context")
	}
	close(b.release)
}

func TestVerifyDummyDerivesOnceAndNeverSucceeds(t *testing.T) {
	var calls atomic.Int32
	h := newHasher(func(p, s []byte, tt, m uint32, th uint8, k uint32) []byte {
		calls.Add(1)
		if m != argonMemory || tt != argonTime || th != argonThreads {
			t.Errorf("dummy verification uses m=%d t=%d p=%d, want the current parameters", m, tt, th)
		}
		return make([]byte, k) // all zero: the very key stored in the dummy
	})
	if err := h.VerifyDummy(context.Background(), "anything"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("%d derivations, want exactly 1", calls.Load())
	}
}
