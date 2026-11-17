package crypto

import (
	"bytes"
	"testing"
)

func testKey() [32]byte {
	var k [32]byte
	copy(k[:], "0123456789abcdef0123456789abcdef")
	return k
}

func TestSealRoundTrip(t *testing.T) {
	key := testKey()
	sealed, err := Seal(key, []byte("radius-secret-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, []byte("radius-secret-1")) {
		t.Fatal("sealed payload contains plaintext")
	}
	plain, err := Open(key, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plain) != "radius-secret-1" {
		t.Errorf("round trip = %q", plain)
	}
}

func TestSealUsesRandomNonce(t *testing.T) {
	key := testKey()
	a, err := Seal(key, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two seals of the same plaintext are identical; nonce must be random")
	}
}

func TestSealRejectsEmpty(t *testing.T) {
	if _, err := Seal(testKey(), nil); err == nil {
		t.Error("Seal(nil) = nil, want error")
	}
}

func TestOpenFailsClosed(t *testing.T) {
	key := testKey()
	sealed, err := Seal(key, []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	var other [32]byte
	copy(other[:], "ffffffffffffffffffffffffffffffff")

	cases := []struct {
		name string
		key  [32]byte
		data []byte
	}{
		{"wrong key", other, sealed},
		{"truncated", key, sealed[:5]},
		{"empty", key, nil},
		{"flipped bit", key, flipBit(sealed)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(tc.key, tc.data); err == nil {
				t.Error("Open = nil, want authentication failure")
			}
		})
	}
}

func flipBit(b []byte) []byte {
	out := bytes.Clone(b)
	out[len(out)-1] ^= 0x01
	return out
}
