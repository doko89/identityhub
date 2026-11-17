package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/identityhub/identityhub/internal/domain"
)

const spMetadataNoCert = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/slo-post"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/slo"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`

func TestParseSPMetadata(t *testing.T) {
	sp, err := ParseSPMetadata(spMetadataNoCert)
	if err != nil {
		t.Fatalf("ParseSPMetadata: %v", err)
	}
	if sp.EntityID != "https://sp.example.com/metadata" {
		t.Fatalf("EntityID = %q", sp.EntityID)
	}
	if sp.ACSURL != "https://sp.example.com/acs" {
		t.Fatalf("ACSURL = %q", sp.ACSURL)
	}
	if sp.SLOURL != "https://sp.example.com/slo" {
		t.Fatalf("SLOURL = %q, want the Redirect endpoint", sp.SLOURL)
	}
	if sp.CertPEM != "" {
		t.Fatalf("CertPEM should be empty, got %q", sp.CertPEM)
	}
	if sp.MetadataXML != spMetadataNoCert {
		t.Fatal("raw XML must be kept for audit")
	}
}

func TestParseSPMetadataWithCert(t *testing.T) {
	key := testKey(t)
	cert, _, err := selfSignedCert(key)
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(cert.Raw)
	raw := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://signed.example.com/metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>` + b64 + `</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://signed.example.com/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`
	sp, err := ParseSPMetadata(raw)
	if err != nil {
		t.Fatalf("ParseSPMetadata: %v", err)
	}
	if !strings.Contains(sp.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("CertPEM is not PEM: %q", sp.CertPEM)
	}
	if sp.SLOURL != "" {
		t.Fatalf("SLOURL = %q, want empty when no SLO endpoint", sp.SLOURL)
	}
	// The stored cert must rebuild into valid registry metadata.
	if _, err := SPEntityDescriptor(sp); err != nil {
		t.Fatalf("SPEntityDescriptor: %v", err)
	}
}

func TestParseSPMetadataRejects(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"not xml":        "this is not xml",
		"no entity":      `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"></EntityDescriptor>`,
		"no sp sso":      `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"></EntityDescriptor>`,
		"no post acs":    `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://x/artifact" index="0"/></SPSSODescriptor></EntityDescriptor>`,
		"oversized":      strings.Repeat("x", maxSPMetadataBytes+1),
		"bad cert bytes": strings.Replace(spMetadataNoCert, "<SingleLogoutService", `<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>bm90LWEuY2VydA==</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleLogoutService`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			sp, err := ParseSPMetadata(raw)
			if name == "bad cert bytes" {
				// Unparseable certs are skipped, not fatal: the SP simply
				// has no key, so unsigned requests still work.
				if err != nil {
					t.Fatalf("unparseable cert must be skipped, got %v", err)
				}
				if sp.CertPEM != "" {
					t.Fatalf("CertPEM = %q, want empty", sp.CertPEM)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestSPEntityDescriptorCorruptCert(t *testing.T) {
	sp := domain.SAMLServiceProvider{
		EntityID: "https://x.example.com", ACSURL: "https://x.example.com/acs",
		CertPEM: "not pem",
	}
	if _, err := SPEntityDescriptor(sp); err == nil {
		t.Fatal("expected error for corrupt stored certificate")
	}
}

func TestRenderSPMetadataRoundTrip(t *testing.T) {
	sp, err := ParseSPMetadata(spMetadataNoCert)
	if err != nil {
		t.Fatalf("ParseSPMetadata: %v", err)
	}
	out, err := RenderSPMetadata(sp)
	if err != nil {
		t.Fatalf("RenderSPMetadata: %v", err)
	}
	back, err := ParseSPMetadata(out)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if back.EntityID != sp.EntityID || back.ACSURL != sp.ACSURL || back.SLOURL != sp.SLOURL {
		t.Fatalf("round trip mismatch: %+v vs %+v", back, sp)
	}
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return key
}
