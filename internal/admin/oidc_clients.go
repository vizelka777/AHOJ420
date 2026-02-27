package admin

import (
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

type OIDCClientHandler struct {
	store OIDCClientStore
}

func NewOIDCClientHandler(clientStore OIDCClientStore) *OIDCClientHandler {
	return &OIDCClientHandler{store: clientStore}
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
	var req createOIDCClientRequest
	if err := decodeJSON(c, &req); err != nil {
		logAdminAction("admin.oidc_client.create", "", 0, c.RealIP(), false, err)
		return writeError(c, http.StatusBadRequest, "invalid request body")
	}

	clientID := strings.TrimSpace(req.ID)
	if clientID == "" {
		logAdminAction("admin.oidc_client.create", "", 0, c.RealIP(), false, errors.New("missing client id"))
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	initialSecret := strings.TrimSpace(req.InitialSecret)
	if req.Confidential && initialSecret == "" {
		logAdminAction("admin.oidc_client.create", clientID, 0, c.RealIP(), false, errors.New("missing initial secret"))
		return writeError(c, http.StatusBadRequest, "initial_secret is required for confidential clients")
	}
	if !req.Confidential && initialSecret != "" {
		logAdminAction("admin.oidc_client.create", clientID, 0, c.RealIP(), false, errors.New("initial secret provided for public client"))
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

	secrets := []store.OIDCClientSecretInput{}
	if req.Confidential {
		secrets = append(secrets, store.OIDCClientSecretInput{
			PlainSecret: initialSecret,
			Label:       strings.TrimSpace(req.InitialSecretLabel),
		})
	}

	err := h.store.CreateOIDCClient(client, secrets)
	if err != nil {
		logAdminAction("admin.oidc_client.create", clientID, 0, c.RealIP(), false, err)
		return writeMappedStoreError(c, err)
	}

	detail, err := h.getClientDetail(clientID)
	if err != nil {
		logAdminAction("admin.oidc_client.create", clientID, 0, c.RealIP(), false, err)
		return writeMappedStoreError(c, err)
	}

	logAdminAction("admin.oidc_client.create", clientID, 0, c.RealIP(), true, nil)
	return c.JSON(http.StatusCreated, detail)
}

func (h *OIDCClientHandler) UpdateOIDCClient(c echo.Context) error {
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		logAdminAction("admin.oidc_client.update", "", 0, c.RealIP(), false, errors.New("missing client id"))
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	var req updateOIDCClientRequest
	if err := decodeJSON(c, &req); err != nil {
		logAdminAction("admin.oidc_client.update", clientID, 0, c.RealIP(), false, err)
		return writeError(c, http.StatusBadRequest, "invalid request body")
	}

	current, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		logAdminAction("admin.oidc_client.update", clientID, 0, c.RealIP(), false, err)
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
		logAdminAction("admin.oidc_client.update", clientID, 0, c.RealIP(), false, err)
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

	if err := h.store.UpdateOIDCClient(updated); err != nil {
		logAdminAction("admin.oidc_client.update", clientID, 0, c.RealIP(), false, err)
		return writeMappedStoreError(c, err)
	}

	detail, err := h.getClientDetail(clientID)
	if err != nil {
		logAdminAction("admin.oidc_client.update", clientID, 0, c.RealIP(), false, err)
		return writeMappedStoreError(c, err)
	}

	logAdminAction("admin.oidc_client.update", clientID, 0, c.RealIP(), true, nil)
	return c.JSON(http.StatusOK, detail)
}

func (h *OIDCClientHandler) ReplaceOIDCClientRedirectURIs(c echo.Context) error {
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		logAdminAction("admin.oidc_client.redirect_uris.replace", "", 0, c.RealIP(), false, errors.New("missing client id"))
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	var req replaceRedirectURIsRequest
	if err := decodeJSON(c, &req); err != nil {
		logAdminAction("admin.oidc_client.redirect_uris.replace", clientID, 0, c.RealIP(), false, err)
		return writeError(c, http.StatusBadRequest, "invalid request body")
	}
	normalizedURIs := normalizeStringList(req.RedirectURIs)
	if len(normalizedURIs) == 0 {
		logAdminAction("admin.oidc_client.redirect_uris.replace", clientID, 0, c.RealIP(), false, errors.New("empty redirect uris"))
		return writeError(c, http.StatusBadRequest, "redirect_uris must not be empty")
	}

	if err := h.store.ReplaceOIDCClientRedirectURIs(clientID, normalizedURIs); err != nil {
		logAdminAction("admin.oidc_client.redirect_uris.replace", clientID, 0, c.RealIP(), false, err)
		return writeMappedStoreError(c, err)
	}

	detail, err := h.getClientDetail(clientID)
	if err != nil {
		logAdminAction("admin.oidc_client.redirect_uris.replace", clientID, 0, c.RealIP(), false, err)
		return writeMappedStoreError(c, err)
	}

	logAdminAction("admin.oidc_client.redirect_uris.replace", clientID, 0, c.RealIP(), true, nil)
	return c.JSON(http.StatusOK, detail)
}

func (h *OIDCClientHandler) AddOIDCClientSecret(c echo.Context) error {
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		logAdminAction("admin.oidc_client.secret.add", "", 0, c.RealIP(), false, errors.New("missing client id"))
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	var req addOIDCClientSecretRequest
	if err := decodeJSON(c, &req); err != nil {
		logAdminAction("admin.oidc_client.secret.add", clientID, 0, c.RealIP(), false, err)
		return writeError(c, http.StatusBadRequest, "invalid request body")
	}

	plainSecret := strings.TrimSpace(req.Secret)
	if req.Generate && plainSecret != "" {
		logAdminAction("admin.oidc_client.secret.add", clientID, 0, c.RealIP(), false, errors.New("generate and secret together"))
		return writeError(c, http.StatusBadRequest, "provide either generate=true or secret, not both")
	}
	if req.Generate {
		generated, err := generateSecret()
		if err != nil {
			logAdminAction("admin.oidc_client.secret.add", clientID, 0, c.RealIP(), false, err)
			return writeError(c, http.StatusInternalServerError, "failed to generate secret")
		}
		plainSecret = generated
	}
	if plainSecret == "" {
		logAdminAction("admin.oidc_client.secret.add", clientID, 0, c.RealIP(), false, errors.New("missing secret"))
		return writeError(c, http.StatusBadRequest, "secret is required")
	}

	if err := h.store.AddOIDCClientSecret(clientID, plainSecret, strings.TrimSpace(req.Label)); err != nil {
		logAdminAction("admin.oidc_client.secret.add", clientID, 0, c.RealIP(), false, err)
		return writeMappedStoreError(c, err)
	}

	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		logAdminAction("admin.oidc_client.secret.add", clientID, 0, c.RealIP(), false, err)
		return writeError(c, http.StatusInternalServerError, "failed to list oidc client secrets")
	}

	latest := latestActiveSecret(secrets)
	if latest == nil {
		err := errors.New("added secret was not found")
		logAdminAction("admin.oidc_client.secret.add", clientID, 0, c.RealIP(), false, err)
		return writeError(c, http.StatusInternalServerError, "failed to load created secret")
	}

	resp := addOIDCClientSecretResponse{Secret: newOIDCClientSecretDTO(*latest)}
	if req.Generate {
		resp.PlainSecret = plainSecret
	}

	logAdminAction("admin.oidc_client.secret.add", clientID, latest.ID, c.RealIP(), true, nil)
	return c.JSON(http.StatusCreated, resp)
}

func (h *OIDCClientHandler) RevokeOIDCClientSecret(c echo.Context) error {
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		logAdminAction("admin.oidc_client.secret.revoke", "", 0, c.RealIP(), false, errors.New("missing client id"))
		return writeError(c, http.StatusBadRequest, "client id is required")
	}

	secretIDRaw := strings.TrimSpace(c.Param("secretID"))
	secretID, err := strconv.ParseInt(secretIDRaw, 10, 64)
	if err != nil || secretID <= 0 {
		logAdminAction("admin.oidc_client.secret.revoke", clientID, 0, c.RealIP(), false, errors.New("invalid secret id"))
		return writeError(c, http.StatusBadRequest, "invalid secret id")
	}

	if err := h.store.RevokeOIDCClientSecret(clientID, secretID); err != nil {
		logAdminAction("admin.oidc_client.secret.revoke", clientID, secretID, c.RealIP(), false, err)
		return writeMappedStoreError(c, err)
	}

	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		logAdminAction("admin.oidc_client.secret.revoke", clientID, secretID, c.RealIP(), false, err)
		return writeError(c, http.StatusInternalServerError, "failed to list oidc client secrets")
	}

	logAdminAction("admin.oidc_client.secret.revoke", clientID, secretID, c.RealIP(), true, nil)
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

func logAdminAction(action string, clientID string, secretID int64, realIP string, success bool, err error) {
	if success {
		log.Printf("admin action=%s client_id=%s secret_id=%d ip=%s success=true", action, clientID, secretID, realIP)
		return
	}
	log.Printf("admin action=%s client_id=%s secret_id=%d ip=%s success=false error=%v", action, clientID, secretID, realIP, err)
}
