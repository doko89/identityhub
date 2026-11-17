package crypto

import (
	"bytes"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP parameters (PRD §6.6): 6-digit codes, 30-second steps, SHA-1.
const (
	totpPeriodSeconds = 30
	totpDigits        = 6
	totpSecretSize    = 20
)

// TOTP implements domain.TOTP on pquerna/otp. It is stateless: all state
// (seeds, last steps) lives behind the domain.MFAStore port.
type TOTP struct{}

// NewSeed generates a fresh random seed and its otpauth:// URL.
func (TOTP) NewSeed(issuer, account string) ([]byte, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      totpPeriodSeconds,
		SecretSize:  totpSecretSize,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, "", fmt.Errorf("crypto: totp seed: %w", err)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper(key.Secret()))
	if err != nil {
		return nil, "", fmt.Errorf("crypto: totp seed decode: %w", err)
	}
	return raw, key.URL(), nil
}

// Verify matches code against the current step or the previous one only
// (PRD §6.6 narrow window). The future step never matches, and
// comparison is constant-time.
func (TOTP) Verify(seed []byte, code string, at time.Time) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	step := at.Unix() / totpPeriodSeconds
	for _, s := range []int64{step, step - 1} {
		if s < 0 {
			continue
		}
		want, err := totp.GenerateCodeCustom(secret,
			time.Unix(s*totpPeriodSeconds, 0).UTC(),
			totp.ValidateOpts{Period: totpPeriodSeconds, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// Code returns the code for one absolute step.
func (TOTP) Code(seed []byte, step int64) (string, error) {
	if step < 0 {
		return "", fmt.Errorf("crypto: totp step must not be negative")
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	return totp.GenerateCodeCustom(secret,
		time.Unix(step*totpPeriodSeconds, 0).UTC(),
		totp.ValidateOpts{Period: totpPeriodSeconds, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}

// QRCodePNG renders content as a size×size PNG QR image for the enroll
// page (PRD §6.6: QR enroll). The otpauth URL is also returned as text
// so manual entry stays possible without the image.
func (TOTP) QRCodePNG(content string, size int) ([]byte, error) {
	if content == "" || size <= 0 {
		return nil, fmt.Errorf("crypto: qr content and a positive size are required")
	}
	code, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return nil, fmt.Errorf("crypto: qr encode: %w", err)
	}
	scaled, err := barcode.Scale(code, size, size)
	if err != nil {
		return nil, fmt.Errorf("crypto: qr scale: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, scaled); err != nil {
		return nil, fmt.Errorf("crypto: qr png: %w", err)
	}
	return buf.Bytes(), nil
}
