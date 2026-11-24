package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const stripTestEntity = "https://sp.example.com/metadata"

func stripTestXML(t *testing.T, withSig bool) string {
	t.Helper()
	sig := ""
	if withSig {
		sig = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo><ds:SignatureValue>QUJD</ds:SignatureValue></ds:Signature>`
	}
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc" Version="2.0" IssueInstant="2026-11-24T04:00:00Z">` +
		sig +
		`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` + stripTestEntity + `</saml:Issuer></samlp:AuthnRequest>`
}

func TestStripRedirectSignature(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest=AAA&RelayState=r&SigAlg=x&Signature=yyy", nil)
	out, ok := stripRedirectSignature(req)
	if !ok {
		t.Fatal("signed redirect must strip")
	}
	q := out.URL.Query()
	if q.Get("Signature") != "" || q.Get("SigAlg") != "" {
		t.Fatalf("signature params remain: %q", out.URL.RawQuery)
	}
	if q.Get("SAMLRequest") != "AAA" || q.Get("RelayState") != "r" {
		t.Fatalf("payload mangled: %q", out.URL.RawQuery)
	}
	plain := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest=AAA", nil)
	if _, ok := stripRedirectSignature(plain); ok {
		t.Fatal("unsigned redirect must report nothing to strip")
	}
}

func TestStripPOSTSimpleSign(t *testing.T) {
	form := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(stripTestXML(t, false)))},
		"RelayState":  {"r"},
		"SigAlg":      {"x"},
		"Signature":   {"yyy"},
	}
	req := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out, ok := stripPOSTSignature([]byte(form.Encode()), req)
	if !ok {
		t.Fatal("simplesign POST must strip")
	}
	if err := out.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if out.PostForm.Get("Signature") != "" || out.PostForm.Get("SigAlg") != "" {
		t.Fatal("signature params remain")
	}
	raw, err := base64.StdEncoding.DecodeString(out.PostForm.Get("SAMLRequest"))
	if err != nil || !strings.Contains(string(raw), stripTestEntity) {
		t.Fatalf("SAMLRequest mangled: %q %v", raw, err)
	}
}

func TestStripPOSTEnveloped(t *testing.T) {
	form := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(stripTestXML(t, true)))},
		"RelayState":  {"r"},
	}
	req := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out, ok := stripPOSTSignature([]byte(form.Encode()), req)
	if !ok {
		t.Fatal("enveloped POST must strip")
	}
	if err := out.ParseForm(); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(out.PostForm.Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Signature") {
		t.Fatalf("signature remains: %s", raw)
	}
	if !strings.Contains(string(raw), stripTestEntity) {
		t.Fatalf("issuer lost: %s", raw)
	}
	var probe any
	if err := xml.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("stripped XML not well-formed: %v", err)
	}
}

func TestStripPOSTNothingToStrip(t *testing.T) {
	// Unsigned body.
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(stripTestXML(t, false)))}}
	req := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))
	if _, ok := stripPOSTSignature([]byte(form.Encode()), req); ok {
		t.Fatal("unsigned POST must report nothing to strip")
	}
	// Undecodable body: leave it alone so the original error stands.
	bad := url.Values{"SAMLRequest": {"!!!not-base64!!!"}}
	req2 := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(bad.Encode()))
	if _, ok := stripPOSTSignature([]byte(bad.Encode()), req2); ok {
		t.Fatal("undecodable POST must report nothing to strip")
	}
}

func TestStripEnvelopedSignaturePrefixes(t *testing.T) {
	// Non-ds prefix + paired tags with attributes.
	raw := `<samlp:AuthnRequest xmlns:samlp="urn:x" ID="_1"><s:Signature xmlns:s="http://www.w3.org/2000/09/xmldsig#" ID="s1"><s:X/></s:Signature><saml:Issuer>e</saml:Issuer></samlp:AuthnRequest>`
	out, ok := stripEnvelopedSignature([]byte(raw))
	if !ok {
		t.Fatal("must strip s:-prefixed Signature")
	}
	if strings.Contains(string(out), "Signature") {
		t.Fatalf("signature remains: %s", out)
	}
	var probe any
	if err := xml.Unmarshal(out, &probe); err != nil {
		t.Fatalf("stripped XML not well-formed: %v", err)
	}
	// Self-closing form.
	rawSelf := `<samlp:AuthnRequest xmlns:samlp="urn:x" ID="_1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><saml:Issuer>e</saml:Issuer></samlp:AuthnRequest>`
	if _, ok := stripEnvelopedSignature([]byte(rawSelf)); !ok {
		t.Fatal("must strip self-closing Signature")
	}
	// No signature at all.
	if _, ok := stripEnvelopedSignature([]byte(`<a><b/></a>`)); ok {
		t.Fatal("must report nothing to strip")
	}
}
