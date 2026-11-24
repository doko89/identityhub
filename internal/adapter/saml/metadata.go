package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"strings"

	csaml "github.com/crewjam/saml"

	"github.com/identityhub/identityhub/internal/domain"
)

// maxSPMetadataBytes caps imported SP metadata (PRD §6.4). Real SP
// metadata is a few KB; 1 MB leaves ample headroom without letting a
// pasted file exhaust memory.
const maxSPMetadataBytes = 1 << 20

// MetadataParser implements domain.SAMLMetadataParser: the registration
// flow parses through it so usecases never touch the SAML library.
type MetadataParser struct{}

// ParseSPMetadata implements domain.SAMLMetadataParser.
func (MetadataParser) ParseSPMetadata(raw string) (domain.SAMLServiceProvider, error) {
	return ParseSPMetadata(raw)
}

// ParseSPMetadata imports an SP metadata document (PRD §6.4: SP metadata
// import) into registry fields. It picks the default POST assertion
// consumer service, the preferred single-logout endpoint, and the first
// signing certificate; the raw XML is kept for audit.
func ParseSPMetadata(raw string) (domain.SAMLServiceProvider, error) {
	if len(raw) == 0 || len(raw) > maxSPMetadataBytes {
		return domain.SAMLServiceProvider{}, fmt.Errorf("%w: SP metadata must be 1 byte-1 MB", domain.ErrValidation)
	}
	var ed csaml.EntityDescriptor
	if err := xml.Unmarshal([]byte(raw), &ed); err != nil {
		return domain.SAMLServiceProvider{}, fmt.Errorf("%w: SP metadata is not valid XML: %v", domain.ErrValidation, err)
	}
	if ed.EntityID == "" {
		return domain.SAMLServiceProvider{}, fmt.Errorf("%w: SP metadata has no entityID", domain.ErrValidation)
	}
	if len(ed.SPSSODescriptors) == 0 {
		return domain.SAMLServiceProvider{}, fmt.Errorf("%w: SP metadata has no SPSSODescriptor", domain.ErrValidation)
	}
	desc := ed.SPSSODescriptors[0]
	acs := pickACS(desc.AssertionConsumerServices)
	if acs == "" {
		return domain.SAMLServiceProvider{}, fmt.Errorf("%w: SP metadata has no HTTP-POST assertion consumer service", domain.ErrValidation)
	}
	certPEM, err := signingCertPEM(desc.KeyDescriptors)
	if err != nil {
		return domain.SAMLServiceProvider{}, fmt.Errorf("%w: SP signing certificate: %v", domain.ErrValidation, err)
	}
	return domain.SAMLServiceProvider{
		EntityID:    ed.EntityID,
		ACSURL:      acs,
		SLOURL:      pickSLO(desc.SingleLogoutServices),
		MetadataXML: raw,
		CertPEM:     certPEM,
	}, nil
}

// pickACS returns the default POST ACS location: the isDefault endpoint
// when it speaks POST, else the first POST/SimpleSign endpoint.
func pickACS(eps []csaml.IndexedEndpoint) string {
	for _, ep := range eps {
		if ep.IsDefault != nil && *ep.IsDefault && isPostBinding(ep.Binding) {
			return strings.TrimSpace(ep.Location)
		}
	}
	for _, ep := range eps {
		if isPostBinding(ep.Binding) && strings.TrimSpace(ep.Location) != "" {
			return strings.TrimSpace(ep.Location)
		}
	}
	return ""
}

// pickSLO prefers the Redirect logout endpoint, then POST, then anything.
func pickSLO(eps []csaml.Endpoint) string {
	for _, binding := range []string{csaml.HTTPRedirectBinding, csaml.HTTPPostBinding, ""} {
		for _, ep := range eps {
			if (binding == "" || ep.Binding == binding) && strings.TrimSpace(ep.Location) != "" {
				return strings.TrimSpace(ep.Location)
			}
		}
	}
	return ""
}

func isPostBinding(binding string) bool {
	return binding == csaml.HTTPPostBinding || binding == csaml.HTTPPostSimpleSignBinding
}

// signingCertPEM extracts the first signing (or use-unspecified) X.509
// certificate as PEM. Empty means the SP advertises no key: its requests
// skip signature verification (Authentik parity) while every other check
// still applies.
func signingCertPEM(keys []csaml.KeyDescriptor) (string, error) {
	for _, kd := range keys {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(stripWhitespace(xc.Data))
			if err != nil || len(der) == 0 {
				continue
			}
			if _, err := x509.ParseCertificate(der); err != nil {
				continue
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
		}
	}
	return "", nil
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}

// SPEntityDescriptor rebuilds crewjam metadata from a registry row so the
// IdP validates AuthnRequests against exactly what was registered:
// issuer match, ACS match, and signature verification with the stored
// certificate.
func SPEntityDescriptor(sp domain.SAMLServiceProvider) (*csaml.EntityDescriptor, error) {
	isDefault := true
	ed := &csaml.EntityDescriptor{EntityID: sp.EntityID}
	desc := csaml.SPSSODescriptor{
		AssertionConsumerServices: []csaml.IndexedEndpoint{{
			Binding:   csaml.HTTPPostBinding,
			Location:  sp.ACSURL,
			Index:     0,
			IsDefault: &isDefault,
		}},
	}
	if sp.SLOURL != "" {
		desc.SingleLogoutServices = []csaml.Endpoint{{
			Binding:  csaml.HTTPRedirectBinding,
			Location: sp.SLOURL,
		}}
	}
	if sp.CertPEM != "" {
		block, _ := pem.Decode([]byte(sp.CertPEM))
		if block == nil {
			return nil, fmt.Errorf("saml: SP %q has a corrupt stored certificate", sp.EntityID)
		}
		desc.KeyDescriptors = []csaml.KeyDescriptor{{
			Use: "signing",
			KeyInfo: csaml.KeyInfo{
				X509Data: csaml.X509Data{
					X509Certificates: []csaml.X509Certificate{{
						Data: base64.StdEncoding.EncodeToString(block.Bytes),
					}},
				},
			},
		}}
	}
	ed.SPSSODescriptors = []csaml.SPSSODescriptor{desc}
	return ed, nil
}

// RenderSPMetadata renders a registry row back to metadata XML (handy for
// tests and for showing what was imported). It round-trips through the
// same descriptor the IdP validates against.
func RenderSPMetadata(sp domain.SAMLServiceProvider) (string, error) {
	ed, err := SPEntityDescriptor(sp)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(ed); err != nil {
		return "", err
	}
	return buf.String(), nil
}
