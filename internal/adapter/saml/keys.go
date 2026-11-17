// Package saml wraps crewjam/saml behind the domain.SAMLProvider port
// (TECH_SPEC §2): AuthnRequest parsing/validation, assertion building and
// signing come from the library; the SP registry, attribute mapping and
// login decisions stay in our code. No other package imports crewjam/saml
// — the swap boundary is this package plus domain/saml.go.
package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the minimal SQL surface keys need (mirrors adapter/oidc).
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// KeyPair is the IdP signing identity: RSA key + self-signed certificate
// advertised in the IdP metadata.
type KeyPair struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
	KID  string
}

// certLifetime bounds the self-signed IdP certificate. Rotation is a
// manual re-registration with SPs (documented in INTEGRATION.md).
const certLifetime = 10 * 365 * 24 * time.Hour

// LoadOrGenerateKey returns the IdP signing identity, generating and
// persisting one on first boot. The kid is stable across restarts because
// it is stored with the key in saml_keys.
func LoadOrGenerateKey(ctx context.Context, q Querier) (KeyPair, error) {
	const getQ = `SELECT kid, key_pem, cert_pem FROM saml_keys ORDER BY created_at LIMIT 1`
	var kid, keyPEM, certPEM string
	err := q.QueryRow(ctx, getQ).Scan(&kid, &keyPEM, &certPEM)
	if err == nil {
		key, cert, err := parsePair(keyPEM, certPEM)
		if err != nil {
			return KeyPair{}, fmt.Errorf("saml: stored signing identity is corrupt: %w", err)
		}
		return KeyPair{Key: key, Cert: cert, KID: kid}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return KeyPair{}, fmt.Errorf("saml: load signing identity: %w", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyPair{}, fmt.Errorf("saml: generate signing key: %w", err)
	}
	cert, certPEM, err := selfSignedCert(key)
	if err != nil {
		return KeyPair{}, err
	}
	kid = "saml-" + uuid.NewString()[:8]
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return KeyPair{}, fmt.Errorf("saml: marshal signing key: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	const insQ = `INSERT INTO saml_keys (kid, key_pem, cert_pem) VALUES ($1,$2,$3) ON CONFLICT (kid) DO NOTHING`
	if _, err := q.Exec(ctx, insQ, kid, keyPEM, certPEM); err != nil {
		return KeyPair{}, fmt.Errorf("saml: store signing identity: %w", err)
	}
	return KeyPair{Key: key, Cert: cert, KID: kid}, nil
}

// selfSignedCert mints the IdP signing certificate. The subject carries
// the generic IdentityHub name; SPs pin the key, not the subject.
func selfSignedCert(key *rsa.PrivateKey) (*x509.Certificate, string, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("saml: certificate serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "IdentityHub SAML IdP"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", fmt.Errorf("saml: create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("saml: parse certificate: %w", err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return cert, pemText, nil
}

func parsePair(keyPEM, certPEM string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, nil, errors.New("no PEM block in key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("key is not RSA")
	}
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, nil, errors.New("no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}
