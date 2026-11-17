package crypto

// Sealer binds Seal/Open to one ENC_KEY so usecases depend on the
// domain.SeedSealer port instead of package-level key threading.
type Sealer struct {
	Key [32]byte
}

// Seal encrypts plaintext with the bound key.
func (s Sealer) Seal(plaintext []byte) ([]byte, error) {
	return Seal(s.Key, plaintext)
}

// Open decrypts a Seal payload with the bound key.
func (s Sealer) Open(sealed []byte) ([]byte, error) {
	return Open(s.Key, sealed)
}
