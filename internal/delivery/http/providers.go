package http

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	usecaseapp "github.com/identityhub/identityhub/internal/usecase/app"
)

// ---------- admin: OIDC clients ----------

func oidcClientJSON(c domain.OIDCClient) map[string]any {
	return map[string]any{
		"application_id": c.ApplicationID.String(), "client_id": c.ClientID,
		"redirect_uris": c.RedirectURIs, "scopes": c.Scopes,
		"public": len(c.ClientSecretHash) == 0,
	}
}

// handleAdminListOIDCClients pages registered clients (hashes stripped).
func (h *Handlers) handleAdminListOIDCClients(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePage(req.URL.Query().Get)
	out, total, err := h.providers.ListOIDCClients(req.Context(), limit, offset)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	clients := make([]any, 0, len(out))
	for _, c := range out {
		clients = append(clients, oidcClientJSON(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients, "total": total})
}

type adminOIDCClientRequest struct {
	ApplicationID string   `json:"application_id"`
	ClientID      string   `json:"client_id"`
	RedirectURIs  []string `json:"redirect_uris"`
	Scopes        []string `json:"scopes"`
	Public        bool     `json:"public"`
}

// handleAdminCreateOIDCClient registers a client. The plaintext secret is
// returned once (confidential clients); it cannot be recovered later.
func (h *Handlers) handleAdminCreateOIDCClient(w http.ResponseWriter, req *http.Request) {
	var in adminOIDCClientRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	appID, err := uuid.Parse(in.ApplicationID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid application id"})
		return
	}
	created, secret, err := h.providers.RegisterOIDCClient(req.Context(), usecaseapp.RegisterOIDCClientInput{
		ApplicationID: appID, ClientID: in.ClientID,
		RedirectURIs: in.RedirectURIs, Scopes: in.Scopes, Public: in.Public,
	})
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	// The usecase strips the hash before returning, so the public flag
	// cannot be derived from it here: a non-empty secret means the
	// client is confidential.
	clientJSON := oidcClientJSON(created)
	clientJSON["public"] = secret == ""
	resp := map[string]any{"client": clientJSON}
	if secret != "" {
		resp["client_secret"] = secret
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleAdminDeleteOIDCClient removes a client by its public client_id.
func (h *Handlers) handleAdminDeleteOIDCClient(w http.ResponseWriter, req *http.Request) {
	if err := h.providers.DeleteOIDCClient(req.Context(), req.PathValue("clientID")); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- admin: SAML SPs ----------

func samlSPJSON(sp domain.SAMLServiceProvider) map[string]any {
	return map[string]any{
		"application_id": sp.ApplicationID.String(), "entity_id": sp.EntityID,
		"acs_url": sp.ACSURL, "slo_url": sp.SLOURL, "name_id": sp.NameID,
	}
}

// handleAdminListSAMLSPs pages registered SPs.
func (h *Handlers) handleAdminListSAMLSPs(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePage(req.URL.Query().Get)
	out, total, err := h.providers.ListSAMLSPs(req.Context(), limit, offset)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	sps := make([]any, 0, len(out))
	for _, sp := range out {
		sps = append(sps, samlSPJSON(sp))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sps": sps, "total": total})
}

type adminSAMLSPRequest struct {
	ApplicationID string `json:"application_id"`
	MetadataXML   string `json:"metadata_xml"`
	NameID        string `json:"name_id"`
}

// maxSPMetadataBody caps the SP-import request body: the metadata ceiling
// (1 MB) plus JSON overhead. decodeJSON's 1 MB cap is too tight here.
const maxSPMetadataBody = 2 << 20

func decodeJSONLimit(w http.ResponseWriter, req *http.Request, v any, limit int64) bool {
	defer req.Body.Close()
	dec := json.NewDecoder(io.LimitReader(req.Body, limit))
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

// handleAdminImportSAMLSP registers an SP from pasted metadata XML.
func (h *Handlers) handleAdminImportSAMLSP(w http.ResponseWriter, req *http.Request) {
	var in adminSAMLSPRequest
	if !decodeJSONLimit(w, req, &in, maxSPMetadataBody) {
		return
	}
	appID, err := uuid.Parse(in.ApplicationID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid application id"})
		return
	}
	sp, err := h.providers.ImportSAMLSP(req.Context(), usecaseapp.ImportSAMLSPInput{
		ApplicationID: appID, MetadataXML: in.MetadataXML, NameID: in.NameID,
	})
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"sp": samlSPJSON(sp)})
}

// handleAdminDeleteSAMLSP removes an SP by entity_id (query parameter:
// entity ids are URLs and cannot travel in a path segment).
func (h *Handlers) handleAdminDeleteSAMLSP(w http.ResponseWriter, req *http.Request) {
	if err := h.providers.DeleteSAMLSP(req.Context(), req.URL.Query().Get("entity_id")); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- admin: RADIUS NAS clients ----------

func radiusClientJSON(c domain.RADIUSClient) map[string]any {
	return map[string]any{
		"application_id": c.ApplicationID.String(), "nas_identifier": c.NASIdentifier,
	}
}

// handleAdminListRADIUSClients pages NAS clients (secrets stripped).
func (h *Handlers) handleAdminListRADIUSClients(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePage(req.URL.Query().Get)
	out, total, err := h.providers.ListRADIUSClients(req.Context(), limit, offset)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	clients := make([]any, 0, len(out))
	for _, c := range out {
		clients = append(clients, radiusClientJSON(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients, "total": total})
}

type adminRADIUSClientRequest struct {
	ApplicationID string `json:"application_id"`
	NASIdentifier string `json:"nas_identifier"`
	SharedSecret  string `json:"shared_secret"`
}

// handleAdminCreateRADIUSClient registers a NAS device. The plaintext
// secret is returned once; only sealed bytes are stored.
func (h *Handlers) handleAdminCreateRADIUSClient(w http.ResponseWriter, req *http.Request) {
	var in adminRADIUSClientRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	appID, err := uuid.Parse(in.ApplicationID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid application id"})
		return
	}
	created, secret, err := h.providers.RegisterRADIUSClient(req.Context(), usecaseapp.RegisterRADIUSClientInput{
		ApplicationID: appID, NASIdentifier: in.NASIdentifier, SharedSecret: in.SharedSecret,
	})
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client": radiusClientJSON(created), "shared_secret": secret,
	})
}

// handleAdminDeleteRADIUSClient removes a NAS client by identifier.
func (h *Handlers) handleAdminDeleteRADIUSClient(w http.ResponseWriter, req *http.Request) {
	if err := h.providers.DeleteRADIUSClient(req.Context(), req.PathValue("nas")); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
