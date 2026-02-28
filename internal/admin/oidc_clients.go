package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
	"github.com/lib/pq"
)

type OIDCClientStore interface {
	ListOIDCClients() ([]store.OIDCClient, error)
	GetOIDCClient(id string) (*store.OIDCClient, error)
	ListOIDCClientSecrets(clientID string) ([]store.OIDCClientSecret, error)
	CreateOIDCClient(client store.OIDCClient, secrets []store.OIDCClientSecretInput) error
	UpdateOIDCClient(client store.OIDCClient) error
	ReplaceOIDCClientRedirectURIs(clientID string, uris []string) error
	AddOIDCClientSecret(clientID string, plainSecret string, label string) error
	RevokeOIDCClientSecret(clientID string, secretID int64) error
}

type OIDCClientReloader interface {
	ReloadClients(ctx context.Context) error
}

type AdminAuditStore interface {
	CreateAdminAuditEntry(ctx context.Context, entry store.AdminAuditEntry) error
}

type OIDCClientHandler struct {
	store      OIDCClientStore
	reloader   OIDCClientReloader
	auditStore AdminAuditStore
}

func NewOIDCClientHandler(clientStore OIDCClientStore, reloader OIDCClientReloader, auditStore AdminAuditStore) *OIDCClientHandler {
	return &OIDCClientHandler{store: clientStore, reloader: reloader, auditStore: auditStore}
}

func RegisterOIDCClientRoutes(group *echo.Group, handler *OIDCClientHandler) {
	group.GET("/oidc/clients", handler.ListOIDCClients)
	group.GET("/oidc/clients/:id", handler.GetOIDCClient)
	group.POST("/oidc/clients", handler.CreateOIDCClient)
	group.PUT("/oidc/clients/:id", handler.UpdateOIDCClient)
	group.PUT("/oidc/clients/:id/redirect-uris", handler.ReplaceOIDCClientRedirectURIs)
	group.POST("/oidc/clients/:id/secrets", handler.AddOIDCClientSecret)
	group.POST("/oidc/clients/:id/secrets/:secretID/revoke", handler.RevokeOIDCClientSecret)
}

type oidcClientDTO struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Enabled            bool      `json:"enabled"`
	Confidential       bool      `json:"confidential"`
	RequirePKCE        bool      `json:"require_pkce"`
	AuthMethod         string    `json:"auth_method"`
	GrantTypes         []string  `json:"grant_types"`
	ResponseTypes      []string  `json:"response_types"`
	Scopes             []string  `json:"scopes"`
	RedirectURIs       []string  `json:"redirect_uris"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	ActiveSecretCount  int       `json:"active_secret_count"`
	RevokedSecretCount int       `json:"revoked_secret_count"`
}

type oidcClientSecretDTO struct {
	ID        int64      `json:"id"`
	Label     string     `json:"label"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Status    string     `json:"status"`
}

type oidcClientDetailResponse struct {
	Client  oidcClientDTO         `json:"client"`
	Secrets []oidcClientSecretDTO `json:"secrets"`
}

type createOIDCClientRequest struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Enabled            *bool    `json:"enabled"`
	Confidential       bool     `json:"confidential"`
	RequirePKCE        *bool    `json:"require_pkce"`
	AuthMethod         string   `json:"auth_method"`
	GrantTypes         []string `json:"grant_types"`
	ResponseTypes      []string `json:"response_types"`
	Scopes             []string `json:"scopes"`
	RedirectURIs       []string `json:"redirect_uris"`
	InitialSecret      string   `json:"initial_secret"`
	InitialSecretLabel string   `json:"initial_secret_label"`
}

type updateOIDCClientRequest struct {
	Name          *string   `json:"name"`
	Enabled       *bool     `json:"enabled"`
	Confidential  *bool     `json:"confidential"`
	RequirePKCE   *bool     `json:"require_pkce"`
	AuthMethod    *string   `json:"auth_method"`
	GrantTypes    *[]string `json:"grant_types"`
	ResponseTypes *[]string `json:"response_types"`
	Scopes        *[]string `json:"scopes"`
}

type replaceRedirectURIsRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
}

type addOIDCClientSecretRequest struct {
	Secret   string `json:"secret"`
	Label    string `json:"label"`
	Generate bool   `json:"generate"`
}

type addOIDCClientSecretResponse struct {
	Secret      oidcClientSecretDTO `json:"secret"`
	PlainSecret string              `json:"plain_secret,omitempty"`
}

type revokeOIDCClientSecretResponse struct {
	Secrets []oidcClientSecretDTO `json:"secrets"`
}

func (h *OIDCClientHandler) ListOIDCClients(c echo.Context) error {
	clients, err := h.store.ListOIDCClients()
	if err != nil {
		return writeError(c, http.StatusInternalServerError, "failed to list oidc clients")
	}

	enabledFilterRaw := strings.TrimSpace(c.QueryParam("enabled"))
	enabledFilter := false
	enabledFilterSet := false
	if enabledFilterRaw != "" {
		parsed, parseErr := strconv.ParseBool(enabledFilterRaw)
		if parseErr != nil {
			return writeError(c, http.StatusBadRequest, "invalid enabled filter")
		}
		enabledFilter = parsed
		enabledFilterSet = true
	}
	query := strings.ToLower(strings.TrimSpace(c.QueryParam("q")))

	items := make([]oidcClientDTO, 0, len(clients))
	for _, client := range clients {
		if enabledFilterSet && client.Enabled != enabledFilter {
			continue
		}
		if query != "" {
			if !strings.Contains(strings.ToLower(client.ID), query) &&
				!strings.Contains(strings.ToLower(client.Name), query) {
				continue
			}
		}

		secrets, secretsErr := h.store.ListOIDCClientSecrets(client.ID)
		if secretsErr != nil {
			return writeError(c, http.StatusInternalServerError, "failed to list oidc client secrets")
		}
		active, revoked := secretCounts(secrets)
		items = append(items, newOIDCClientDTO(client, active, revoked))
	}

	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return c.JSON(http.StatusOK, map[string]any{"clients": items})
}

func (h *OIDCClientHandler) GetOIDCClient(c echo.Context) error {
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	client, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		if errors.Is(err, store.ErrOIDCClientNotFound) {
			return writeError(c, http.StatusNotFound, "oidc client not found")
		}
		return writeError(c, http.StatusInternalServerError, "failed to get oidc client")
	}

	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		return writeError(c, http.StatusInternalServerError, "failed to list oidc client secrets")
	}
	active, revoked := secretCounts(secrets)

	return c.JSON(http.StatusOK, oidcClientDetailResponse{
		Client:  newOIDCClientDTO(*client, active, revoked),
		Secrets: newOIDCClientSecretDTOs(secrets),
	})
}

func (h *OIDCClientHandler) CreateOIDCClient(c echo.Context) error {
	action := "admin.oidc_client.create"
	clientID := ""
	var secretID int64
	details := map[string]any{}
	success := false
	var opErr error
	defer func() {
		h.logAndAudit(c, action, clientID, secretID, success, opErr, details)
	}()

	var req createOIDCClientRequest
	if err := decodeJSON(c, &req); err != nil {
		opErr = err
		details["error"] = "invalid_request_body"
		return writeError(c, http.StatusBadRequest, "invalid request body")
	}

	clientID = strings.TrimSpace(req.ID)
	if clientID == "" {
		opErr = errors.New("missing client id")
		details["error"] = "missing_client_id"
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	initialSecret := strings.TrimSpace(req.InitialSecret)
	if req.Confidential && initialSecret == "" {
		opErr = errors.New("missing initial secret")
		details["error"] = "missing_initial_secret"
		return writeError(c, http.StatusBadRequest, "initial_secret is required for confidential clients")
	}
	if !req.Confidential && initialSecret != "" {
		opErr = errors.New("initial secret provided for public client")
		details["error"] = "initial_secret_for_public_client"
		return writeError(c, http.StatusBadRequest, "initial_secret is not allowed for public clients")
	}

	client := store.OIDCClient{
		ID:            clientID,
		Name:          strings.TrimSpace(req.Name),
		Enabled:       boolOrDefault(req.Enabled, true),
		Confidential:  req.Confidential,
		RequirePKCE:   boolOrDefault(req.RequirePKCE, true),
		AuthMethod:    strings.TrimSpace(req.AuthMethod),
		GrantTypes:    append([]string(nil), req.GrantTypes...),
		ResponseTypes: append([]string(nil), req.ResponseTypes...),
		Scopes:        append([]string(nil), req.Scopes...),
		RedirectURIs:  append([]string(nil), req.RedirectURIs...),
	}
	details = clientAuditDetails(client)

	secrets := []store.OIDCClientSecretInput{}
	if req.Confidential {
		secrets = append(secrets, store.OIDCClientSecretInput{
			PlainSecret: initialSecret,
			Label:       strings.TrimSpace(req.InitialSecretLabel),
		})
		details["initial_secret_label"] = strings.TrimSpace(req.InitialSecretLabel)
	}

	if err := h.store.CreateOIDCClient(client, secrets); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}
	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return writeError(c, http.StatusInternalServerError, "client created in storage but runtime reload failed")
	}

	detail, err := h.getClientDetail(clientID)
	if err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}

	success = true
	return c.JSON(http.StatusCreated, detail)
}

func (h *OIDCClientHandler) UpdateOIDCClient(c echo.Context) error {
	action := "admin.oidc_client.update"
	clientID := strings.TrimSpace(c.Param("id"))
	var secretID int64
	details := map[string]any{}
	success := false
	var opErr error
	defer func() {
		h.logAndAudit(c, action, clientID, secretID, success, opErr, details)
	}()

	if clientID == "" {
		opErr = errors.New("missing client id")
		details["error"] = "missing_client_id"
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	var req updateOIDCClientRequest
	if err := decodeJSON(c, &req); err != nil {
		opErr = err
		details["error"] = "invalid_request_body"
		return writeError(c, http.StatusBadRequest, "invalid request body")
	}

	current, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}

	updated := *current
	if req.Name != nil {
		updated.Name = strings.TrimSpace(*req.Name)
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.Confidential != nil && *req.Confidential != current.Confidential {
		err := errors.New("confidential flag change is not supported in mvp")
		opErr = err
		details["error"] = "confidential_flag_change_not_supported"
		return writeError(c, http.StatusConflict, "confidential flag change is not supported in mvp")
	}
	if req.RequirePKCE != nil {
		updated.RequirePKCE = *req.RequirePKCE
	}
	if req.AuthMethod != nil {
		updated.AuthMethod = strings.TrimSpace(*req.AuthMethod)
	}
	if req.GrantTypes != nil {
		updated.GrantTypes = append([]string(nil), (*req.GrantTypes)...)
	}
	if req.ResponseTypes != nil {
		updated.ResponseTypes = append([]string(nil), (*req.ResponseTypes)...)
	}
	if req.Scopes != nil {
		updated.Scopes = append([]string(nil), (*req.Scopes)...)
	}
	details = clientAuditDetails(updated)

	if err := h.store.UpdateOIDCClient(updated); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}
	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return writeError(c, http.StatusInternalServerError, "client updated in storage but runtime reload failed")
	}

	detail, err := h.getClientDetail(clientID)
	if err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}

	success = true
	return c.JSON(http.StatusOK, detail)
}

func (h *OIDCClientHandler) ReplaceOIDCClientRedirectURIs(c echo.Context) error {
	action := "admin.oidc_client.redirect_uris.replace"
	clientID := strings.TrimSpace(c.Param("id"))
	var secretID int64
	details := map[string]any{}
	success := false
	var opErr error
	defer func() {
		h.logAndAudit(c, action, clientID, secretID, success, opErr, details)
	}()

	if clientID == "" {
		opErr = errors.New("missing client id")
		details["error"] = "missing_client_id"
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	var req replaceRedirectURIsRequest
	if err := decodeJSON(c, &req); err != nil {
		opErr = err
		details["error"] = "invalid_request_body"
		return writeError(c, http.StatusBadRequest, "invalid request body")
	}
	normalizedURIs := normalizeStringList(req.RedirectURIs)
	details["redirect_uri_count"] = len(normalizedURIs)
	if len(normalizedURIs) == 0 {
		opErr = errors.New("empty redirect uris")
		details["error"] = "empty_redirect_uris"
		return writeError(c, http.StatusBadRequest, "redirect_uris must not be empty")
	}

	if err := h.store.ReplaceOIDCClientRedirectURIs(clientID, normalizedURIs); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}
	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return writeError(c, http.StatusInternalServerError, "client redirect uris replaced in storage but runtime reload failed")
	}

	detail, err := h.getClientDetail(clientID)
	if err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}
	details["enabled"] = detail.Client.Enabled
	details["confidential"] = detail.Client.Confidential
	details["auth_method"] = detail.Client.AuthMethod
	details["grant_types"] = append([]string(nil), detail.Client.GrantTypes...)
	details["response_types"] = append([]string(nil), detail.Client.ResponseTypes...)
	details["scope_count"] = len(detail.Client.Scopes)

	success = true
	return c.JSON(http.StatusOK, detail)
}

func (h *OIDCClientHandler) AddOIDCClientSecret(c echo.Context) error {
	action := "admin.oidc_client.secret.add"
	clientID := strings.TrimSpace(c.Param("id"))
	var secretID int64
	details := map[string]any{}
	success := false
	var opErr error
	defer func() {
		h.logAndAudit(c, action, clientID, secretID, success, opErr, details)
	}()

	if clientID == "" {
		opErr = errors.New("missing client id")
		details["error"] = "missing_client_id"
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	var req addOIDCClientSecretRequest
	if err := decodeJSON(c, &req); err != nil {
		opErr = err
		details["error"] = "invalid_request_body"
		return writeError(c, http.StatusBadRequest, "invalid request body")
	}
	details["generated"] = req.Generate
	details["label"] = strings.TrimSpace(req.Label)

	plainSecret := strings.TrimSpace(req.Secret)
	if req.Generate && plainSecret != "" {
		opErr = errors.New("generate and secret together")
		details["error"] = "generate_and_secret_together"
		return writeError(c, http.StatusBadRequest, "provide either generate=true or secret, not both")
	}
	if req.Generate {
		generated, err := generateSecret()
		if err != nil {
			opErr = err
			details["error"] = "secret_generation_failed"
			return writeError(c, http.StatusInternalServerError, "failed to generate secret")
		}
		plainSecret = generated
	}
	if plainSecret == "" {
		opErr = errors.New("missing secret")
		details["error"] = "missing_secret"
		return writeError(c, http.StatusBadRequest, "secret is required")
	}

	if err := h.store.AddOIDCClientSecret(clientID, plainSecret, strings.TrimSpace(req.Label)); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}

	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeError(c, http.StatusInternalServerError, "failed to list oidc client secrets")
	}

	latest := latestActiveSecret(secrets)
	if latest == nil {
		opErr = errors.New("added secret was not found")
		details["error"] = "added_secret_not_found"
		return writeError(c, http.StatusInternalServerError, "failed to load created secret")
	}
	secretID = latest.ID

	resp := addOIDCClientSecretResponse{Secret: newOIDCClientSecretDTO(*latest)}
	if req.Generate {
		resp.PlainSecret = plainSecret
	}
	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return writeError(c, http.StatusInternalServerError, "client secret added in storage but runtime reload failed")
	}
	details["secret_id"] = latest.ID
	details["label"] = latest.Label
	details["generated"] = req.Generate

	success = true
	return c.JSON(http.StatusCreated, resp)
}

func (h *OIDCClientHandler) RevokeOIDCClientSecret(c echo.Context) error {
	action := "admin.oidc_client.secret.revoke"
	clientID := strings.TrimSpace(c.Param("id"))
	var secretID int64
	details := map[string]any{}
	success := false
	var opErr error
	defer func() {
		h.logAndAudit(c, action, clientID, secretID, success, opErr, details)
	}()

	if clientID == "" {
		opErr = errors.New("missing client id")
		details["error"] = "missing_client_id"
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	secretIDRaw := strings.TrimSpace(c.Param("secretID"))
	parsedSecretID, err := strconv.ParseInt(secretIDRaw, 10, 64)
	secretID = parsedSecretID
	details["secret_id"] = secretID
	if err != nil || secretID <= 0 {
		opErr = errors.New("invalid secret id")
		details["error"] = "invalid_secret_id"
		return writeError(c, http.StatusBadRequest, "invalid secret id")
	}

	if err := h.store.RevokeOIDCClientSecret(clientID, secretID); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeMappedStoreError(c, err)
	}
	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return writeError(c, http.StatusInternalServerError, "client secret revoked in storage but runtime reload failed")
	}

	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		return writeError(c, http.StatusInternalServerError, "failed to list oidc client secrets")
	}
	details["revoked"] = true

	success = true
	return c.JSON(http.StatusOK, revokeOIDCClientSecretResponse{
		Secrets: newOIDCClientSecretDTOs(secrets),
	})
}

func (h *OIDCClientHandler) getClientDetail(clientID string) (*oidcClientDetailResponse, error) {
	client, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		return nil, err
	}
	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		return nil, err
	}
	active, revoked := secretCounts(secrets)
	return &oidcClientDetailResponse{
		Client:  newOIDCClientDTO(*client, active, revoked),
		Secrets: newOIDCClientSecretDTOs(secrets),
	}, nil
}

func newOIDCClientDTO(client store.OIDCClient, activeSecrets int, revokedSecrets int) oidcClientDTO {
	return oidcClientDTO{
		ID:                 client.ID,
		Name:               client.Name,
		Enabled:            client.Enabled,
		Confidential:       client.Confidential,
		RequirePKCE:        client.RequirePKCE,
		AuthMethod:         client.AuthMethod,
		GrantTypes:         append([]string(nil), client.GrantTypes...),
		ResponseTypes:      append([]string(nil), client.ResponseTypes...),
		Scopes:             append([]string(nil), client.Scopes...),
		RedirectURIs:       append([]string(nil), client.RedirectURIs...),
		CreatedAt:          client.CreatedAt,
		UpdatedAt:          client.UpdatedAt,
		ActiveSecretCount:  activeSecrets,
		RevokedSecretCount: revokedSecrets,
	}
}

func newOIDCClientSecretDTO(secret store.OIDCClientSecret) oidcClientSecretDTO {
	status := "active"
	if secret.RevokedAt != nil {
		status = "revoked"
	}
	return oidcClientSecretDTO{
		ID:        secret.ID,
		Label:     secret.Label,
		CreatedAt: secret.CreatedAt,
		RevokedAt: secret.RevokedAt,
		Status:    status,
	}
}

func newOIDCClientSecretDTOs(secrets []store.OIDCClientSecret) []oidcClientSecretDTO {
	out := make([]oidcClientSecretDTO, 0, len(secrets))
	for _, secret := range secrets {
		out = append(out, newOIDCClientSecretDTO(secret))
	}
	return out
}

func secretCounts(secrets []store.OIDCClientSecret) (active int, revoked int) {
	for _, secret := range secrets {
		if secret.RevokedAt == nil {
			active++
		} else {
			revoked++
		}
	}
	return active, revoked
}

func latestActiveSecret(secrets []store.OIDCClientSecret) *store.OIDCClientSecret {
	for _, secret := range secrets {
		if secret.RevokedAt == nil {
			item := secret
			return &item
		}
	}
	return nil
}

func boolOrDefault(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
	}
	return *value
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func generateSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeJSON(c echo.Context, out any) error {
	decoder := json.NewDecoder(c.Request().Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func writeMappedStoreError(c echo.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrOIDCClientNotFound):
		return writeError(c, http.StatusNotFound, "oidc client not found")
	case errors.Is(err, store.ErrOIDCClientSecretNotFound):
		return writeError(c, http.StatusNotFound, "oidc client secret not found")
	case isConflictError(err):
		return writeError(c, http.StatusConflict, err.Error())
	case isBadRequestError(err):
		return writeError(c, http.StatusBadRequest, err.Error())
	default:
		return writeError(c, http.StatusInternalServerError, "internal server error")
	}
}

func isConflictError(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "must keep at least one active secret") ||
		strings.Contains(msg, "public client must not have secrets") ||
		strings.Contains(msg, "public client has no secrets")
}

func isBadRequestError(err error) bool {
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "is required") ||
		strings.Contains(msg, "at least one redirect_uri is required") ||
		strings.Contains(msg, "unsupported auth_method") ||
		strings.Contains(msg, "confidential client requires")
}

func writeError(c echo.Context, status int, message string) error {
	return c.JSON(status, map[string]string{"message": message})
}

func (h *OIDCClientHandler) reloadRuntime(ctx context.Context) error {
	if h.reloader == nil {
		return nil
	}
	return h.reloader.ReloadClients(ctx)
}

func (h *OIDCClientHandler) logAndAudit(c echo.Context, action string, clientID string, secretID int64, success bool, opErr error, details map[string]any) {
	requestID := requestIDFromContext(c)
	realIP := strings.TrimSpace(c.RealIP())

	if success {
		log.Printf("admin action=%s client_id=%s secret_id=%d ip=%s request_id=%s success=true", action, clientID, secretID, realIP, requestID)
	} else {
		log.Printf("admin action=%s client_id=%s secret_id=%d ip=%s request_id=%s success=false error=%v", action, clientID, secretID, realIP, requestID, opErr)
	}

	if h.auditStore == nil {
		return
	}

	entry := store.AdminAuditEntry{
		Action:       strings.TrimSpace(action),
		Success:      success,
		ActorType:    "token",
		ActorID:      "admin_api_token",
		RemoteIP:     realIP,
		RequestID:    requestID,
		ResourceType: "oidc_client",
		ResourceID:   strings.TrimSpace(clientID),
		DetailsJSON:  buildAuditDetailsJSON(details, secretID, opErr),
	}
	if err := h.auditStore.CreateAdminAuditEntry(c.Request().Context(), entry); err != nil {
		log.Printf("admin audit insert failed action=%s client_id=%s secret_id=%d request_id=%s error=%v", action, clientID, secretID, requestID, err)
	}
}

func buildAuditDetailsJSON(details map[string]any, secretID int64, opErr error) json.RawMessage {
	payload := map[string]any{}
	for key, value := range details {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		// Keep only safe metadata keys for admin audit.
		if strings.Contains(trimmedKey, "plain_secret") || strings.Contains(trimmedKey, "secret_hash") {
			continue
		}
		payload[trimmedKey] = value
	}
	if secretID > 0 {
		payload["secret_id"] = secretID
	}
	if opErr != nil && payload["error"] == nil {
		payload["error"] = auditErrorCode(opErr)
	}
	if len(payload) == 0 {
		return json.RawMessage(`{}`)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return encoded
}

func clientAuditDetails(client store.OIDCClient) map[string]any {
	return map[string]any{
		"enabled":            client.Enabled,
		"confidential":       client.Confidential,
		"auth_method":        strings.TrimSpace(client.AuthMethod),
		"grant_types":        append([]string(nil), client.GrantTypes...),
		"response_types":     append([]string(nil), client.ResponseTypes...),
		"redirect_uri_count": len(client.RedirectURIs),
		"scope_count":        len(client.Scopes),
	}
}

func auditErrorCode(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, store.ErrOIDCClientNotFound):
		return "oidc_client_not_found"
	case errors.Is(err, store.ErrOIDCClientSecretNotFound):
		return "oidc_client_secret_not_found"
	case isConflictError(err):
		return "conflict"
	case isBadRequestError(err):
		return "bad_request"
	default:
		return "internal_error"
	}
}
