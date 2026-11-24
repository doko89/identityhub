package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// maxAuthnBodyBytes caps the POST body buffered for signature-skipping
// (mirrors the delivery cap; stripped bodies are always smaller).
const maxAuthnBodyBytes = 1 << 20

// stripRedirectSignature clones a Redirect-binding request without its
// query-string signature. It reports false when there is no signature
// to strip.
func stripRedirectSignature(r *http.Request) (*http.Request, bool) {
	q := r.URL.Query()
	if q.Get("Signature") == "" {
		return nil, false
	}
	q.Del("Signature")
	q.Del("SigAlg")
	out := r.Clone(r.Context())
	u := *r.URL
	u.RawQuery = q.Encode()
	out.URL = &u
	out.RequestURI = ""
	clearFormCache(out)
	return out, true
}

// stripPOSTSignature rebuilds a POST-binding request without its
// signature inputs: SimpleSign form params and/or the enveloped XML
// Signature inside SAMLRequest. It reports false when the body carries
// no signature at all (or cannot be decoded — the original error then
// stands).
func stripPOSTSignature(raw []byte, r *http.Request) (*http.Request, bool) {
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, false
	}
	stripped := false
	if form.Get("Signature") != "" {
		form.Del("Signature")
		form.Del("SigAlg")
		stripped = true
	}
	if b64 := form.Get("SAMLRequest"); b64 != "" {
		rawXML, err := base64.StdEncoding.DecodeString(stripWhitespace(b64))
		if err != nil {
			return nil, false
		}
		if unsigned, ok := stripEnvelopedSignature(rawXML); ok {
			form.Set("SAMLRequest", base64.StdEncoding.EncodeToString(unsigned))
			stripped = true
		}
	}
	if !stripped {
		return nil, false
	}
	body := form.Encode()
	out := r.Clone(r.Context())
	out.Body = io.NopCloser(strings.NewReader(body))
	out.ContentLength = int64(len(body))
	out.RequestURI = ""
	clearFormCache(out)
	return out, true
}

// signatureSpan matches one enveloped XML Signature element with any
// namespace prefix (or none), self-closing or paired. The input already
// parsed as XML once (crewjam unmarshalled it before signature checks),
// so a span match here only ever removes well-formed markup; the result
// is re-checked for well-formedness before use.
var signatureSpan = regexp.MustCompile(`(?s)<([A-Za-z_][\w.-]*:)?Signature(\s[^<>]*)?/>|<([A-Za-z_][\w.-]*:)?Signature(\s[^<>]*)?>.*?</([A-Za-z_][\w.-]*:)?Signature\s*>`)

// stripEnvelopedSignature removes enveloped Signature elements from an
// AuthnRequest document. It reports false when there is nothing to
// remove or the remainder is no longer well-formed XML.
func stripEnvelopedSignature(rawXML []byte) ([]byte, bool) {
	if !bytes.Contains(rawXML, []byte("Signature")) {
		return nil, false
	}
	cut := signatureSpan.ReplaceAll(rawXML, nil)
	if bytes.Equal(cut, rawXML) {
		return nil, false
	}
	var probe any
	if err := xml.Unmarshal(cut, &probe); err != nil {
		return nil, false
	}
	return cut, true
}

// clearFormCache drops parsed-form state so the library re-parses the
// rebuilt request from scratch. Request.Clone shares these maps with
// the original, which still describes the signed bytes.
func clearFormCache(r *http.Request) {
	r.Form = nil
	r.PostForm = nil
	r.MultipartForm = nil
}
