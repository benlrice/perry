package vault

import (
	"testing"
	"time"
)

func useTempConfig(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PERRY_IDENTITY", "")
	t.Setenv("PERRY_RECIPIENTS", "")
}

func TestCacheRoundTripAndDrop(t *testing.T) {
	useTempConfig(t)
	t.Cleanup(func() { CacheDrop() })
	if _, _, ok, err := CacheGet(); err != nil || ok {
		t.Skipf("keyring unavailable or dirty: ok=%v err=%v", ok, err)
	}
	if _, err := CachePut("AGE-SECRET-KEY-FAKE", time.Minute); err != nil {
		t.Skipf("keyring unavailable: %v", err)
	}
	id, exp, ok, err := CacheGet()
	if err != nil || !ok || id != "AGE-SECRET-KEY-FAKE" || !exp.After(time.Now()) {
		t.Fatalf("get: %q %v %v %v", id, exp, ok, err)
	}
	if err := CacheDrop(); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := CacheGet(); ok {
		t.Error("still cached after drop")
	}
	if err := CacheDrop(); err != nil {
		t.Errorf("drop of absent key: %v", err)
	}
}

func TestCacheSubSecondTTLExpires(t *testing.T) {
	useTempConfig(t)
	t.Cleanup(func() { CacheDrop() })
	if _, err := CachePut("x", 200*time.Millisecond); err != nil {
		t.Skipf("keyring unavailable: %v", err)
	}
	if _, _, ok, _ := CacheGet(); !ok {
		t.Fatal("not cached")
	}
	time.Sleep(1300 * time.Millisecond)
	if _, _, ok, _ := CacheGet(); ok {
		t.Error("sub-second TTL must round up to 1s and then expire, not live forever")
	}
}
