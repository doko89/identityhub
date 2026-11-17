package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LoadOrGenerateKey returns the active RSA signing key, generating and
// persisting one on first boot. The kid is stable across restarts because
// it is stored with the key in oidc_keys.
func LoadOrGenerateKey(ctx context.Context, q Querier) (KeyGetter, error) {
	const getQ = `SELECT kid, pem FROM oidc_keys ORDER BY created_at LIMIT 1`
	var kid, pemText string
	err := q.QueryRow(ctx, getQ).Scan(&kid, &pemText)
	if err == nil {
		key, err := parsePrivateKey(pemText)
		if err != nil {
			return KeyGetter{}, fmt.Errorf("oidc: stored signing key is corrupt: %w", err)
		}
		return KeyGetter{Key: key, KID: kid}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return KeyGetter{}, fmt.Errorf("oidc: load signing key: %w", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyGetter{}, fmt.Errorf("oidc: generate signing key: %w", err)
	}
	kid = "ih-" + uuid.NewString()[:8]
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return KeyGetter{}, fmt.Errorf("oidc: marshal signing key: %w", err)
	}
	pemText = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	const insQ = `INSERT INTO oidc_keys (kid, pem) VALUES ($1,$2) ON CONFLICT (kid) DO NOTHING`
	if _, err := q.Exec(ctx, insQ, kid, pemText); err != nil {
		return KeyGetter{}, fmt.Errorf("oidc: store signing key: %w", err)
	}
	return KeyGetter{Key: key, KID: kid}, nil
}

func parsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}
	return key, nil
}
