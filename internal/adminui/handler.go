package adminui

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/houbamydar/AHOJ420/internal/admin"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
	"github.com/lib/pq"
)

const (
	flashCookieName  = "admin_ui_flash"
	auditLogPageSize = 25
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
	ListAdminAuditEntries(ctx context.Context, opts store.AdminAuditListOptions) ([]store.AdminAuditEntry, error)
}

type SessionAuth interface {
	SessionUser(c echo.Context) (*store.AdminUser, bool)
	LogoutSession(c echo.Context) error
	RequireSessionMiddleware(loginPath string) echo.MiddlewareFunc
	AttachSessionActorMiddleware() echo.MiddlewareFunc
}

type Handler struct {
	store        OIDCClientStore
	reloader     OIDCClientReloader
	auditStore   AdminAuditStore
	auth         SessionAuth
	templatesDir string
}

type flashMessage struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type layoutData struct {
	Title     string
	Admin     *store.AdminUser
	Flash     *flashMessage
	CSRFToken string
}

type dashboardSummary struct {
	Total        int
	Enabled      int
	Confidential int
	Public       int
}

type clientsListItem struct {
	ID                string
	Name              string
	Enabled           bool
	Confidential      bool
	AuthMethod        string
	RedirectURICount  int
	ActiveSecretCount int
	UpdatedAt         time.Time
}

type oidcClientSecretView struct {
	ID        int64
	Label     string
	CreatedAt time.Time
	RevokedAt *time.Time
	Status    string
}

type oidcClientDetailView struct {
	ID                 string
	Name               string
	Enabled            bool
	Confidential       bool
	RequirePKCE        bool
	AuthMethod         string
	GrantTypes         []string
	ResponseTypes      []string
	Scopes             []string
	RedirectURIs       []string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	ActiveSecretCount  int
	RevokedSecretCount int
	Secrets            []oidcClientSecretView
}

type clientsListPageData struct {
	layoutData
	Query   string
	Clients []clientsListItem
}

type dashboardPageData struct {
	layoutData
	Summary dashboardSummary
}

type clientDetailPageData struct {
	layoutData
	Client *oidcClientDetailView
	Error  string
}

type clientFormData struct {
	ID                 string
	Name               string
	Enabled            bool
	Confidential       bool
	RequirePKCE        bool
	AuthMethod         string
	GrantTypesRaw      string
	ResponseTypesRaw   string
	ScopesRaw          string
	RedirectURIsRaw    string
	InitialSecret      string
	InitialSecretLabel string
}

type clientCreatePageData struct {
	layoutData
	Form  clientFormData
	Error string
}

type clientEditPageData struct {
	layoutData
	ClientID      string
	Confidential  bool
	Form          clientFormData
	Error         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	RedirectCount int
}

type redirectURIsPageData struct {
	layoutData
	ClientID        string
	ClientName      string
	RedirectURIsRaw string
	Error           string
}

type secretNewPageData struct {
	layoutData
	ClientID         string
	ClientName       string
	Confidential     bool
	Label            string
	Secret           string
	Generate         bool
	Error            string
	ActiveSecretHint int
}

type secretCreatedPageData struct {
	layoutData
	ClientID     string
	ClientName   string
	SecretID     int64
	Label        string
	PlainSecret  string
	GeneratedAt  time.Time
	BackToClient string
}

type auditLogItem struct {
	CreatedAt    time.Time
	Action       string
	Success      bool
	Actor        string
	ResourceType string
	ResourceID   string
	RequestID    string
	RemoteIP     string
	Details      string
	HasDetails   bool
}

type auditLogPageData struct {
	layoutData
	Entries          []auditLogItem
	FilterAction     string
	FilterSuccess    string
	FilterActor      string
	FilterResourceID string
	Page             int
	PrevURL          string
	NextURL          string
}

func NewHandler(clientStore OIDCClientStore, reloader OIDCClientReloader, auditStore AdminAuditStore, sessionAuth SessionAuth) (*Handler, error) {
	if clientStore == nil {
		return nil, fmt.Errorf("adminui requires oidc client store")
	}
	if sessionAuth == nil {
		return nil, fmt.Errorf("adminui requires session auth")
	}
	if auditStore == nil {
		return nil, fmt.Errorf("adminui requires audit store")
	}

	return &Handler{
		store:        clientStore,
		reloader:     reloader,
		auditStore:   auditStore,
		auth:         sessionAuth,
		templatesDir: resolveTemplatesDir(),
	}, nil
}

func RegisterPublicRoutes(group *echo.Group, handler *Handler) {
	group.GET("/login", handler.LoginPage)
}

func RegisterProtectedRoutes(group *echo.Group, handler *Handler) {
	group.GET("/", handler.Dashboard)
	group.GET("/audit", handler.AuditLog)
	group.POST("/logout", handler.Logout)
	group.GET("/clients", handler.ClientsList)
	group.GET("/clients/new", handler.ClientNew)
	group.POST("/clients/new", handler.ClientCreate)
	group.GET("/clients/:id", handler.ClientDetail)
	group.GET("/clients/:id/edit", handler.ClientEdit)
	group.POST("/clients/:id/edit", handler.ClientUpdate)
	group.GET("/clients/:id/redirect-uris", handler.ClientRedirectURIsEdit)
	group.POST("/clients/:id/redirect-uris", handler.ClientRedirectURIsUpdate)
	group.GET("/clients/:id/secrets/new", handler.ClientSecretNew)
	group.POST("/clients/:id/secrets", handler.ClientSecretAdd)
	group.POST("/clients/:id/secrets/:secretID/revoke", handler.ClientSecretRevoke)
}

func (h *Handler) AuditLog(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	page := parseAuditLogPage(c.QueryParam("page"))
	action := strings.TrimSpace(c.QueryParam("action"))
	successRaw, successFilter := parseAuditSuccessFilter(c.QueryParam("success"))
	actor := strings.TrimSpace(c.QueryParam("actor"))
	resourceID := strings.TrimSpace(c.QueryParam("resource_id"))

	opts := store.AdminAuditListOptions{
		Limit:      auditLogPageSize + 1,
		Offset:     (page - 1) * auditLogPageSize,
		Action:     action,
		Success:    successFilter,
		Actor:      actor,
		ResourceID: resourceID,
	}

	entries, err := h.auditStore.ListAdminAuditEntries(c.Request().Context(), opts)
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to load audit log")
	}

	hasNext := len(entries) > auditLogPageSize
	if hasNext {
		entries = entries[:auditLogPageSize]
	}

	items := make([]auditLogItem, 0, len(entries))
	for _, entry := range entries {
		details, hasDetails := formatAuditDetailsForDisplay(entry.DetailsJSON)
		items = append(items, auditLogItem{
			CreatedAt:    entry.CreatedAt,
			Action:       strings.TrimSpace(entry.Action),
			Success:      entry.Success,
			Actor:        formatAuditActor(entry.ActorType, entry.ActorID),
			ResourceType: defaultDisplay(strings.TrimSpace(entry.ResourceType)),
			ResourceID:   defaultDisplay(strings.TrimSpace(entry.ResourceID)),
			RequestID:    defaultDisplay(strings.TrimSpace(entry.RequestID)),
			RemoteIP:     defaultDisplay(strings.TrimSpace(entry.RemoteIP)),
			Details:      details,
			HasDetails:   hasDetails,
		})
	}

	prevURL := ""
	if page > 1 {
		prevURL = auditLogURL(page-1, action, successRaw, actor, resourceID)
	}
	nextURL := ""
	if hasNext {
		nextURL = auditLogURL(page+1, action, successRaw, actor, resourceID)
	}

	return h.render(c, http.StatusOK, "audit.html", auditLogPageData{
		layoutData:       h.newLayoutData(c, adminUser, "Admin Audit Log"),
		Entries:          items,
		FilterAction:     action,
		FilterSuccess:    successRaw,
		FilterActor:      actor,
		FilterResourceID: resourceID,
		Page:             page,
		PrevURL:          prevURL,
		NextURL:          nextURL,
	})
}

func (h *Handler) LoginPage(c echo.Context) error {
	if _, ok := h.auth.SessionUser(c); ok {
		return c.Redirect(http.StatusFound, "/admin/")
	}

	return h.render(c, http.StatusOK, "login.html", layoutData{
		Title: "Admin Login",
		Flash: h.popFlash(c),
	})
}

func (h *Handler) Logout(c echo.Context) error {
	_ = h.auth.LogoutSession(c)
	h.clearCSRFCookie(c)
	h.setFlash(c, "success", "Signed out")
	return c.Redirect(http.StatusFound, "/admin/login")
}

func (h *Handler) Dashboard(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	clients, err := h.store.ListOIDCClients()
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to load OIDC clients")
	}

	summary := dashboardSummary{Total: len(clients)}
	for _, client := range clients {
		if client.Enabled {
			summary.Enabled++
		}
		if client.Confidential {
			summary.Confidential++
		} else {
			summary.Public++
		}
	}

	return h.render(c, http.StatusOK, "index.html", dashboardPageData{
		layoutData: h.newLayoutData(c, adminUser, "Admin Dashboard"),
		Summary:    summary,
	})
}

func (h *Handler) ClientsList(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	clients, err := h.store.ListOIDCClients()
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to list OIDC clients")
	}

	query := strings.ToLower(strings.TrimSpace(c.QueryParam("q")))
	items := make([]clientsListItem, 0, len(clients))
	for _, client := range clients {
		if query != "" {
			idMatch := strings.Contains(strings.ToLower(client.ID), query)
			nameMatch := strings.Contains(strings.ToLower(client.Name), query)
			if !idMatch && !nameMatch {
				continue
			}
		}

		secrets, err := h.store.ListOIDCClientSecrets(client.ID)
		if err != nil {
			return h.renderInternalError(c, adminUser, "failed to load client secrets")
		}
		active, _ := secretCounts(secrets)
		items = append(items, clientsListItem{
			ID:                client.ID,
			Name:              client.Name,
			Enabled:           client.Enabled,
			Confidential:      client.Confidential,
			AuthMethod:        client.AuthMethod,
			RedirectURICount:  len(client.RedirectURIs),
			ActiveSecretCount: active,
			UpdatedAt:         client.UpdatedAt,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })

	return h.render(c, http.StatusOK, "clients_list.html", clientsListPageData{
		layoutData: h.newLayoutData(c, adminUser, "OIDC Clients"),
		Query:      strings.TrimSpace(c.QueryParam("q")),
		Clients:    items,
	})
}

func (h *Handler) ClientDetail(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		return h.render(c, http.StatusBadRequest, "client_detail.html", clientDetailPageData{
			layoutData: h.newLayoutData(c, adminUser, "Client"),
			Error:      "Client ID is required",
		})
	}

	detail, err := h.getClientDetail(clientID)
	if err != nil {
		status, message := mapStoreError(err)
		return h.render(c, status, "client_detail.html", clientDetailPageData{
			layoutData: h.newLayoutData(c, adminUser, "Client"),
			Error:      message,
		})
	}

	return h.render(c, http.StatusOK, "client_detail.html", clientDetailPageData{
		layoutData: h.newLayoutData(c, adminUser, "Client: "+detail.ID),
		Client:     detail,
	})
}

func (h *Handler) ClientNew(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	form := defaultClientForm()
	return h.render(c, http.StatusOK, "client_new.html", clientCreatePageData{
		layoutData: h.newLayoutData(c, adminUser, "New OIDC Client"),
		Form:       form,
	})
}

func (h *Handler) ClientCreate(c echo.Context) error {
	action := "admin.oidc_client.create"
	adminUser := h.currentAdmin(c)
	form := readClientCreateForm(c)
	details := map[string]any{}
	success := false
	var opErr error
	defer func() {
		h.logAndAudit(c, action, form.ID, 0, success, opErr, details)
	}()

	validationError := validateClientCreateForm(form)
	if validationError != "" {
		opErr = errors.New(validationError)
		details["error"] = "validation_failed"
		return h.render(c, http.StatusBadRequest, "client_new.html", clientCreatePageData{
			layoutData: h.newLayoutData(c, adminUser, "New OIDC Client"),
			Form:       form,
			Error:      validationError,
		})
	}

	grantTypes := parseDelimitedList(form.GrantTypesRaw)
	responseTypes := parseDelimitedList(form.ResponseTypesRaw)
	scopes := parseDelimitedList(form.ScopesRaw)
	redirectURIs := parseLineList(form.RedirectURIsRaw)

	client := store.OIDCClient{
		ID:            strings.TrimSpace(form.ID),
		Name:          strings.TrimSpace(form.Name),
		Enabled:       form.Enabled,
		Confidential:  form.Confidential,
		RequirePKCE:   form.RequirePKCE,
		AuthMethod:    strings.TrimSpace(form.AuthMethod),
		GrantTypes:    grantTypes,
		ResponseTypes: responseTypes,
		Scopes:        scopes,
		RedirectURIs:  redirectURIs,
	}
	secrets := []store.OIDCClientSecretInput{}
	if form.Confidential {
		secrets = append(secrets, store.OIDCClientSecretInput{
			PlainSecret: strings.TrimSpace(form.InitialSecret),
			Label:       strings.TrimSpace(form.InitialSecretLabel),
		})
	}
	details = clientAuditDetails(client)
	details["initial_secret_label"] = strings.TrimSpace(form.InitialSecretLabel)

	if err := h.store.CreateOIDCClient(client, secrets); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		status, message := mapStoreError(err)
		return h.render(c, status, "client_new.html", clientCreatePageData{
			layoutData: h.newLayoutData(c, adminUser, "New OIDC Client"),
			Form:       form,
			Error:      message,
		})
	}

	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return h.render(c, http.StatusInternalServerError, "client_new.html", clientCreatePageData{
			layoutData: h.newLayoutData(c, adminUser, "New OIDC Client"),
			Form:       form,
			Error:      "Client created in storage but runtime reload failed",
		})
	}

	success = true
	h.setFlash(c, "success", "Client created")
	return c.Redirect(http.StatusSeeOther, "/admin/clients/"+client.ID)
}

func (h *Handler) ClientEdit(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	clientID := strings.TrimSpace(c.Param("id"))
	client, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		status, message := mapStoreError(err)
		return h.render(c, status, "client_edit.html", clientEditPageData{
			layoutData: h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			ClientID:   clientID,
			Error:      message,
		})
	}

	form := clientFormData{
		ID:               client.ID,
		Name:             client.Name,
		Enabled:          client.Enabled,
		Confidential:     client.Confidential,
		RequirePKCE:      client.RequirePKCE,
		AuthMethod:       client.AuthMethod,
		GrantTypesRaw:    joinLines(client.GrantTypes),
		ResponseTypesRaw: joinLines(client.ResponseTypes),
		ScopesRaw:        joinLines(client.Scopes),
		RedirectURIsRaw:  joinLines(client.RedirectURIs),
	}

	return h.render(c, http.StatusOK, "client_edit.html", clientEditPageData{
		layoutData:    h.newLayoutData(c, adminUser, "Edit OIDC Client"),
		ClientID:      client.ID,
		Confidential:  client.Confidential,
		Form:          form,
		CreatedAt:     client.CreatedAt,
		UpdatedAt:     client.UpdatedAt,
		RedirectCount: len(client.RedirectURIs),
	})
}

func (h *Handler) ClientUpdate(c echo.Context) error {
	action := "admin.oidc_client.update"
	adminUser := h.currentAdmin(c)
	clientID := strings.TrimSpace(c.Param("id"))
	details := map[string]any{}
	success := false
	var opErr error
	defer func() {
		h.logAndAudit(c, action, clientID, 0, success, opErr, details)
	}()

	if clientID == "" {
		opErr = errors.New("client id is required")
		return h.render(c, http.StatusBadRequest, "client_edit.html", clientEditPageData{
			layoutData: h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			Error:      "Client ID is required",
		})
	}

	current, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		opErr = err
		status, message := mapStoreError(err)
		return h.render(c, status, "client_edit.html", clientEditPageData{
			layoutData: h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			ClientID:   clientID,
			Error:      message,
		})
	}

	form := readClientEditForm(c, current)
	validationError := validateClientEditForm(form)
	if validationError != "" {
		opErr = errors.New(validationError)
		details["error"] = "validation_failed"
		return h.render(c, http.StatusBadRequest, "client_edit.html", clientEditPageData{
			layoutData:    h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			ClientID:      clientID,
			Confidential:  current.Confidential,
			Form:          form,
			CreatedAt:     current.CreatedAt,
			UpdatedAt:     current.UpdatedAt,
			RedirectCount: len(current.RedirectURIs),
			Error:         validationError,
		})
	}

	updated := store.OIDCClient{
		ID:            current.ID,
		Name:          strings.TrimSpace(form.Name),
		Enabled:       form.Enabled,
		Confidential:  current.Confidential,
		RequirePKCE:   form.RequirePKCE,
		AuthMethod:    strings.TrimSpace(form.AuthMethod),
		GrantTypes:    parseDelimitedList(form.GrantTypesRaw),
		ResponseTypes: parseDelimitedList(form.ResponseTypesRaw),
		Scopes:        parseDelimitedList(form.ScopesRaw),
		RedirectURIs:  append([]string(nil), current.RedirectURIs...),
	}
	details = clientAuditDetails(updated)

	if err := h.store.UpdateOIDCClient(updated); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		status, message := mapStoreError(err)
		return h.render(c, status, "client_edit.html", clientEditPageData{
			layoutData:    h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			ClientID:      clientID,
			Confidential:  current.Confidential,
			Form:          form,
			CreatedAt:     current.CreatedAt,
			UpdatedAt:     current.UpdatedAt,
			RedirectCount: len(current.RedirectURIs),
			Error:         message,
		})
	}

	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return h.render(c, http.StatusInternalServerError, "client_edit.html", clientEditPageData{
			layoutData:    h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			ClientID:      clientID,
			Confidential:  current.Confidential,
			Form:          form,
			CreatedAt:     current.CreatedAt,
			UpdatedAt:     current.UpdatedAt,
			RedirectCount: len(current.RedirectURIs),
			Error:         "Client updated in storage but runtime reload failed",
		})
	}

	success = true
	h.setFlash(c, "success", "Client updated")
	return c.Redirect(http.StatusSeeOther, "/admin/clients/"+clientID)
}

func (h *Handler) ClientRedirectURIsEdit(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	clientID := strings.TrimSpace(c.Param("id"))
	client, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		status, message := mapStoreError(err)
		return h.render(c, status, "client_redirect_uris.html", redirectURIsPageData{
			layoutData: h.newLayoutData(c, adminUser, "Edit Redirect URIs"),
			ClientID:   clientID,
			Error:      message,
		})
	}

	return h.render(c, http.StatusOK, "client_redirect_uris.html", redirectURIsPageData{
		layoutData:      h.newLayoutData(c, adminUser, "Edit Redirect URIs"),
		ClientID:        client.ID,
		ClientName:      client.Name,
		RedirectURIsRaw: joinLines(client.RedirectURIs),
	})
}

func (h *Handler) ClientRedirectURIsUpdate(c echo.Context) error {
	action := "admin.oidc_client.redirect_uris.replace"
	adminUser := h.currentAdmin(c)
	clientID := strings.TrimSpace(c.Param("id"))
	details := map[string]any{}
	success := false
	var opErr error
	defer func() {
		h.logAndAudit(c, action, clientID, 0, success, opErr, details)
	}()

	if clientID == "" {
		opErr = errors.New("client id is required")
		return h.render(c, http.StatusBadRequest, "client_redirect_uris.html", redirectURIsPageData{
			layoutData: h.newLayoutData(c, adminUser, "Edit Redirect URIs"),
			Error:      "Client ID is required",
		})
	}

	client, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		opErr = err
		status, message := mapStoreError(err)
		return h.render(c, status, "client_redirect_uris.html", redirectURIsPageData{
			layoutData: h.newLayoutData(c, adminUser, "Edit Redirect URIs"),
			ClientID:   clientID,
			Error:      message,
		})
	}

	redirectURIsRaw := c.FormValue("redirect_uris")
	redirectURIs := parseLineList(redirectURIsRaw)
	details["redirect_uri_count"] = len(redirectURIs)
	if len(redirectURIs) == 0 {
		opErr = errors.New("redirect uris are required")
		details["error"] = "empty_redirect_uris"
		return h.render(c, http.StatusBadRequest, "client_redirect_uris.html", redirectURIsPageData{
			layoutData:      h.newLayoutData(c, adminUser, "Edit Redirect URIs"),
			ClientID:        clientID,
			ClientName:      client.Name,
			RedirectURIsRaw: strings.TrimSpace(redirectURIsRaw),
			Error:           "At least one redirect URI is required",
		})
	}

	if err := h.store.ReplaceOIDCClientRedirectURIs(clientID, redirectURIs); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		status, message := mapStoreError(err)
		return h.render(c, status, "client_redirect_uris.html", redirectURIsPageData{
			layoutData:      h.newLayoutData(c, adminUser, "Edit Redirect URIs"),
			ClientID:        clientID,
			ClientName:      client.Name,
			RedirectURIsRaw: strings.TrimSpace(redirectURIsRaw),
			Error:           message,
		})
	}

	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return h.render(c, http.StatusInternalServerError, "client_redirect_uris.html", redirectURIsPageData{
			layoutData:      h.newLayoutData(c, adminUser, "Edit Redirect URIs"),
			ClientID:        clientID,
			ClientName:      client.Name,
			RedirectURIsRaw: strings.TrimSpace(redirectURIsRaw),
			Error:           "Redirect URIs updated in storage but runtime reload failed",
		})
	}

	success = true
	h.setFlash(c, "success", "Redirect URIs updated")
	return c.Redirect(http.StatusSeeOther, "/admin/clients/"+clientID)
}

func (h *Handler) ClientSecretNew(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	clientID := strings.TrimSpace(c.Param("id"))
	client, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		status, message := mapStoreError(err)
		return h.render(c, status, "secret_new.html", secretNewPageData{
			layoutData: h.newLayoutData(c, adminUser, "Add Secret"),
			ClientID:   clientID,
			Error:      message,
		})
	}

	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to list secrets")
	}
	active, _ := secretCounts(secrets)

	return h.render(c, http.StatusOK, "secret_new.html", secretNewPageData{
		layoutData:       h.newLayoutData(c, adminUser, "Add Secret"),
		ClientID:         client.ID,
		ClientName:       client.Name,
		Confidential:     client.Confidential,
		ActiveSecretHint: active,
	})
}

func (h *Handler) ClientSecretAdd(c echo.Context) error {
	action := "admin.oidc_client.secret.add"
	adminUser := h.currentAdmin(c)
	clientID := strings.TrimSpace(c.Param("id"))
	details := map[string]any{}
	success := false
	var opErr error
	var secretID int64
	defer func() {
		h.logAndAudit(c, action, clientID, secretID, success, opErr, details)
	}()

	client, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		opErr = err
		status, message := mapStoreError(err)
		return h.render(c, status, "secret_new.html", secretNewPageData{
			layoutData: h.newLayoutData(c, adminUser, "Add Secret"),
			ClientID:   clientID,
			Error:      message,
		})
	}
	secretsBefore, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to list existing secrets")
	}
	activeBefore, _ := secretCounts(secretsBefore)

	label := strings.TrimSpace(c.FormValue("label"))
	plainSecret := strings.TrimSpace(c.FormValue("secret"))
	generate := parseCheckboxValue(c.FormValue("generate"))
	details["generated"] = generate
	details["label"] = label

	if !client.Confidential {
		opErr = errors.New("public client has no secrets")
		details["error"] = "public_client_has_no_secrets"
		return h.render(c, http.StatusBadRequest, "secret_new.html", secretNewPageData{
			layoutData:       h.newLayoutData(c, adminUser, "Add Secret"),
			ClientID:         client.ID,
			ClientName:       client.Name,
			Confidential:     client.Confidential,
			Label:            label,
			Secret:           plainSecret,
			Generate:         generate,
			ActiveSecretHint: activeBefore,
			Error:            "Secrets can only be added for confidential clients",
		})
	}

	if generate && plainSecret != "" {
		opErr = errors.New("provide either generated or manual secret")
		details["error"] = "generate_and_secret_together"
		return h.render(c, http.StatusBadRequest, "secret_new.html", secretNewPageData{
			layoutData:       h.newLayoutData(c, adminUser, "Add Secret"),
			ClientID:         client.ID,
			ClientName:       client.Name,
			Confidential:     client.Confidential,
			Label:            label,
			Secret:           plainSecret,
			Generate:         generate,
			ActiveSecretHint: activeBefore,
			Error:            "Provide either a secret value or Generate secret, not both",
		})
	}
	if generate {
		generated, err := generateSecret()
		if err != nil {
			opErr = err
			details["error"] = "secret_generation_failed"
			return h.render(c, http.StatusInternalServerError, "secret_new.html", secretNewPageData{
				layoutData:       h.newLayoutData(c, adminUser, "Add Secret"),
				ClientID:         client.ID,
				ClientName:       client.Name,
				Confidential:     client.Confidential,
				Label:            label,
				Generate:         true,
				ActiveSecretHint: activeBefore,
				Error:            "Failed to generate secret",
			})
		}
		plainSecret = generated
	}

	if plainSecret == "" {
		opErr = errors.New("missing secret")
		details["error"] = "missing_secret"
		return h.render(c, http.StatusBadRequest, "secret_new.html", secretNewPageData{
			layoutData:       h.newLayoutData(c, adminUser, "Add Secret"),
			ClientID:         client.ID,
			ClientName:       client.Name,
			Confidential:     client.Confidential,
			Label:            label,
			Generate:         generate,
			ActiveSecretHint: activeBefore,
			Error:            "Secret is required",
		})
	}

	if err := h.store.AddOIDCClientSecret(clientID, plainSecret, label); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		status, message := mapStoreError(err)
		return h.render(c, status, "secret_new.html", secretNewPageData{
			layoutData:       h.newLayoutData(c, adminUser, "Add Secret"),
			ClientID:         client.ID,
			ClientName:       client.Name,
			Confidential:     client.Confidential,
			Label:            label,
			Secret:           "",
			Generate:         generate,
			ActiveSecretHint: activeBefore,
			Error:            message,
		})
	}

	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		opErr = err
		details["error"] = "list_secrets_failed"
		return h.renderInternalError(c, adminUser, "secret added but failed to load metadata")
	}
	latest := latestActiveSecret(secrets)
	if latest != nil {
		secretID = latest.ID
		details["secret_id"] = latest.ID
	}

	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return h.render(c, http.StatusInternalServerError, "secret_new.html", secretNewPageData{
			layoutData:       h.newLayoutData(c, adminUser, "Add Secret"),
			ClientID:         client.ID,
			ClientName:       client.Name,
			Confidential:     client.Confidential,
			Label:            label,
			Secret:           "",
			Generate:         generate,
			ActiveSecretHint: activeBefore,
			Error:            "Client secret added in storage but runtime reload failed",
		})
	}

	success = true
	if generate {
		return h.render(c, http.StatusOK, "secret_created.html", secretCreatedPageData{
			layoutData:   h.newLayoutData(c, adminUser, "Secret Created"),
			ClientID:     client.ID,
			ClientName:   client.Name,
			SecretID:     secretID,
			Label:        label,
			PlainSecret:  plainSecret,
			GeneratedAt:  time.Now().UTC(),
			BackToClient: "/admin/clients/" + client.ID,
		})
	}

	h.setFlash(c, "success", "Secret added")
	return c.Redirect(http.StatusSeeOther, "/admin/clients/"+client.ID)
}

func (h *Handler) ClientSecretRevoke(c echo.Context) error {
	action := "admin.oidc_client.secret.revoke"
	adminUser := h.currentAdmin(c)
	clientID := strings.TrimSpace(c.Param("id"))
	secretIDRaw := strings.TrimSpace(c.Param("secretID"))
	details := map[string]any{}
	success := false
	var opErr error
	secretID, parseErr := strconv.ParseInt(secretIDRaw, 10, 64)
	if parseErr != nil || secretID <= 0 {
		opErr = errors.New("invalid secret id")
		details["error"] = "invalid_secret_id"
		h.logAndAudit(c, action, clientID, 0, success, opErr, details)
		return h.render(c, http.StatusBadRequest, "client_detail.html", clientDetailPageData{
			layoutData: h.newLayoutData(c, adminUser, "Client"),
			Error:      "Invalid secret ID",
		})
	}
	details["secret_id"] = secretID
	defer func() {
		h.logAndAudit(c, action, clientID, secretID, success, opErr, details)
	}()

	if err := h.store.RevokeOIDCClientSecret(clientID, secretID); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		status, message := mapStoreError(err)
		detail, detailErr := h.getClientDetail(clientID)
		if detailErr != nil {
			return h.render(c, status, "client_detail.html", clientDetailPageData{
				layoutData: h.newLayoutData(c, adminUser, "Client"),
				Error:      message,
			})
		}
		return h.render(c, status, "client_detail.html", clientDetailPageData{
			layoutData: h.newLayoutData(c, adminUser, "Client: "+detail.ID),
			Client:     detail,
			Error:      message,
		})
	}

	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		detail, detailErr := h.getClientDetail(clientID)
		if detailErr != nil {
			return h.render(c, http.StatusInternalServerError, "client_detail.html", clientDetailPageData{
				layoutData: h.newLayoutData(c, adminUser, "Client"),
				Error:      "Secret revoked in storage but runtime reload failed",
			})
		}
		return h.render(c, http.StatusInternalServerError, "client_detail.html", clientDetailPageData{
			layoutData: h.newLayoutData(c, adminUser, "Client: "+detail.ID),
			Client:     detail,
			Error:      "Secret revoked in storage but runtime reload failed",
		})
	}

	success = true
	h.setFlash(c, "success", "Secret revoked")
	return c.Redirect(http.StatusSeeOther, "/admin/clients/"+clientID)
}

func (h *Handler) currentAdmin(c echo.Context) *store.AdminUser {
	if fromCtx, ok := c.Get("admin_user").(*store.AdminUser); ok && fromCtx != nil {
		return fromCtx
	}
	adminUser, _ := h.auth.SessionUser(c)
	return adminUser
}

func (h *Handler) newLayoutData(c echo.Context, adminUser *store.AdminUser, title string) layoutData {
	if adminUser == nil {
		adminUser = h.currentAdmin(c)
	}
	csrfToken := h.csrfToken(c)
	if csrfToken == "" {
		token, err := h.ensureCSRFToken(c)
		if err != nil {
			log.Printf("adminui csrf token init in layout failed error=%v", err)
		} else {
			csrfToken = token
		}
	}
	return layoutData{
		Title:     strings.TrimSpace(title),
		Admin:     adminUser,
		Flash:     h.popFlash(c),
		CSRFToken: csrfToken,
	}
}

func (h *Handler) render(c echo.Context, status int, pageFile string, data any) error {
	layoutPath := filepath.Join(h.templatesDir, "layout.html")
	pagePath := filepath.Join(h.templatesDir, strings.TrimSpace(pageFile))

	tmpl, err := template.New("layout").Funcs(template.FuncMap{
		"formatTime":    formatTime,
		"formatTimePtr": formatTimePtr,
		"joinComma":     joinComma,
		"joinLines":     joinLines,
		"nowUTC": func() time.Time {
			return time.Now().UTC()
		},
	}).ParseFiles(layoutPath, pagePath)
	if err != nil {
		log.Printf("adminui template parse failed file=%s error=%v", pageFile, err)
		return c.String(http.StatusInternalServerError, "template parse error")
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		log.Printf("adminui template execute failed file=%s error=%v", pageFile, err)
		return c.String(http.StatusInternalServerError, "template execute error")
	}

	return c.HTML(status, buf.String())
}

func (h *Handler) renderInternalError(c echo.Context, adminUser *store.AdminUser, message string) error {
	return h.render(c, http.StatusInternalServerError, "client_detail.html", clientDetailPageData{
		layoutData: h.newLayoutData(c, adminUser, "Admin"),
		Error:      strings.TrimSpace(message),
	})
}

func (h *Handler) getClientDetail(clientID string) (*oidcClientDetailView, error) {
	client, err := h.store.GetOIDCClient(clientID)
	if err != nil {
		return nil, err
	}
	secrets, err := h.store.ListOIDCClientSecrets(clientID)
	if err != nil {
		return nil, err
	}
	active, revoked := secretCounts(secrets)

	secretViews := make([]oidcClientSecretView, 0, len(secrets))
	for _, secret := range secrets {
		status := "active"
		if secret.RevokedAt != nil {
			status = "revoked"
		}
		secretViews = append(secretViews, oidcClientSecretView{
			ID:        secret.ID,
			Label:     secret.Label,
			CreatedAt: secret.CreatedAt,
			RevokedAt: secret.RevokedAt,
			Status:    status,
		})
	}

	return &oidcClientDetailView{
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
		ActiveSecretCount:  active,
		RevokedSecretCount: revoked,
		Secrets:            secretViews,
	}, nil
}

func defaultClientForm() clientFormData {
	return clientFormData{
		Enabled:          true,
		Confidential:     false,
		RequirePKCE:      true,
		AuthMethod:       "none",
		GrantTypesRaw:    "authorization_code",
		ResponseTypesRaw: "code",
		ScopesRaw:        "openid\nprofile\nemail\nphone\noffline_access",
	}
}

func readClientCreateForm(c echo.Context) clientFormData {
	form := defaultClientForm()
	form.ID = strings.TrimSpace(c.FormValue("id"))
	form.Name = strings.TrimSpace(c.FormValue("name"))
	form.Enabled = parseCheckboxValue(c.FormValue("enabled"))
	form.Confidential = parseBooleanSelect(c.FormValue("confidential"))
	form.RequirePKCE = parseCheckboxValue(c.FormValue("require_pkce"))
	form.AuthMethod = strings.TrimSpace(c.FormValue("auth_method"))
	form.GrantTypesRaw = strings.TrimSpace(c.FormValue("grant_types"))
	form.ResponseTypesRaw = strings.TrimSpace(c.FormValue("response_types"))
	form.ScopesRaw = strings.TrimSpace(c.FormValue("scopes"))
	form.RedirectURIsRaw = strings.TrimSpace(c.FormValue("redirect_uris"))
	form.InitialSecret = strings.TrimSpace(c.FormValue("initial_secret"))
	form.InitialSecretLabel = strings.TrimSpace(c.FormValue("initial_secret_label"))
	return form
}

func readClientEditForm(c echo.Context, current *store.OIDCClient) clientFormData {
	form := clientFormData{}
	form.ID = strings.TrimSpace(current.ID)
	form.Name = strings.TrimSpace(c.FormValue("name"))
	form.Enabled = parseCheckboxValue(c.FormValue("enabled"))
	form.Confidential = current.Confidential
	form.RequirePKCE = parseCheckboxValue(c.FormValue("require_pkce"))
	form.AuthMethod = strings.TrimSpace(c.FormValue("auth_method"))
	form.GrantTypesRaw = strings.TrimSpace(c.FormValue("grant_types"))
	form.ResponseTypesRaw = strings.TrimSpace(c.FormValue("response_types"))
	form.ScopesRaw = strings.TrimSpace(c.FormValue("scopes"))
	form.RedirectURIsRaw = joinLines(current.RedirectURIs)
	return form
}

func validateClientCreateForm(form clientFormData) string {
	if strings.TrimSpace(form.ID) == "" {
		return "Client ID is required"
	}
	if len(parseLineList(form.RedirectURIsRaw)) == 0 {
		return "At least one redirect URI is required"
	}
	if len(parseDelimitedList(form.GrantTypesRaw)) == 0 {
		return "At least one grant type is required"
	}
	if len(parseDelimitedList(form.ResponseTypesRaw)) == 0 {
		return "At least one response type is required"
	}
	if len(parseDelimitedList(form.ScopesRaw)) == 0 {
		return "At least one scope is required"
	}
	if strings.TrimSpace(form.AuthMethod) == "" {
		return "Auth method is required"
	}
	if form.Confidential {
		if strings.EqualFold(strings.TrimSpace(form.AuthMethod), "none") {
			return "Confidential client cannot use auth_method=none"
		}
		if strings.TrimSpace(form.InitialSecret) == "" {
			return "Initial secret is required for confidential client"
		}
	} else if strings.TrimSpace(form.InitialSecret) != "" {
		return "Initial secret is not allowed for public client"
	}
	return ""
}

func validateClientEditForm(form clientFormData) string {
	if strings.TrimSpace(form.Name) == "" {
		return "Client name is required"
	}
	if strings.TrimSpace(form.AuthMethod) == "" {
		return "Auth method is required"
	}
	if len(parseDelimitedList(form.GrantTypesRaw)) == 0 {
		return "At least one grant type is required"
	}
	if len(parseDelimitedList(form.ResponseTypesRaw)) == 0 {
		return "At least one response type is required"
	}
	if len(parseDelimitedList(form.ScopesRaw)) == 0 {
		return "At least one scope is required"
	}
	return ""
}

func parseDelimitedList(raw string) []string {
	items := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	})
	return normalizeStringList(items)
}

func parseLineList(raw string) []string {
	return normalizeStringList(strings.Split(raw, "\n"))
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func parseCheckboxValue(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

func parseBooleanSelect(raw string) bool {
	raw = strings.ToLower(strings.TrimSpace(raw))
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func parseAuditLogPage(raw string) int {
	page, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || page <= 0 {
		return 1
	}
	return page
}

func parseAuditSuccessFilter(raw string) (string, *bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "success", "true", "1", "yes":
		value := true
		return "success", &value
	case "failure", "false", "0", "no":
		value := false
		return "failure", &value
	default:
		return "", nil
	}
}

func auditLogURL(page int, action string, success string, actor string, resourceID string) string {
	params := url.Values{}
	if page > 1 {
		params.Set("page", strconv.Itoa(page))
	}
	if strings.TrimSpace(action) != "" {
		params.Set("action", strings.TrimSpace(action))
	}
	if strings.TrimSpace(success) != "" {
		params.Set("success", strings.TrimSpace(success))
	}
	if strings.TrimSpace(actor) != "" {
		params.Set("actor", strings.TrimSpace(actor))
	}
	if strings.TrimSpace(resourceID) != "" {
		params.Set("resource_id", strings.TrimSpace(resourceID))
	}
	encoded := params.Encode()
	if encoded == "" {
		return "/admin/audit"
	}
	return "/admin/audit?" + encoded
}

func formatAuditActor(actorType string, actorID string) string {
	actorType = strings.TrimSpace(actorType)
	actorID = strings.TrimSpace(actorID)
	if actorType == "" && actorID == "" {
		return "-"
	}
	if actorType == "" {
		return actorID
	}
	if actorID == "" {
		return actorType
	}
	return actorType + ":" + actorID
}

func defaultDisplay(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func formatAuditDetailsForDisplay(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", false
	}

	sanitized := sanitizeAuditDetails(decoded)
	encoded, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return "", false
	}

	trimmed := strings.TrimSpace(string(encoded))
	if trimmed == "" || trimmed == "{}" || trimmed == "[]" || trimmed == "null" {
		return "", false
	}
	return trimmed, true
}

func sanitizeAuditDetails(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, item := range typed {
			normalized := strings.ToLower(strings.TrimSpace(key))
			if normalized == "" || isSensitiveAuditField(normalized) {
				continue
			}
			out[key] = sanitizeAuditDetails(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeAuditDetails(item))
		}
		return out
	default:
		return value
	}
}

func isSensitiveAuditField(key string) bool {
	return strings.Contains(key, "secret") ||
		strings.Contains(key, "authorization") ||
		strings.Contains(key, "password") ||
		strings.Contains(key, "token")
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func formatTimePtr(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return formatTime(*value)
}

func joinLines(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return strings.Join(items, "\n")
}

func joinComma(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return strings.Join(items, ", ")
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

func (h *Handler) reloadRuntime(ctx context.Context) error {
	if h.reloader == nil {
		return nil
	}
	return h.reloader.ReloadClients(ctx)
}

func mapStoreError(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, store.ErrOIDCClientNotFound):
		return http.StatusNotFound, "OIDC client not found"
	case errors.Is(err, store.ErrOIDCClientSecretNotFound):
		return http.StatusNotFound, "OIDC client secret not found"
	case isConflictError(err):
		return http.StatusConflict, strings.TrimSpace(err.Error())
	case isBadRequestError(err):
		return http.StatusBadRequest, strings.TrimSpace(err.Error())
	default:
		return http.StatusInternalServerError, "Internal server error"
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
		strings.Contains(msg, "public client has no secrets") ||
		strings.Contains(msg, "confidential flag change is not supported")
}

func isBadRequestError(err error) bool {
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "is required") ||
		strings.Contains(msg, "at least one redirect_uri is required") ||
		strings.Contains(msg, "unsupported auth_method") ||
		strings.Contains(msg, "confidential client requires")
}

func generateSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
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

func requestID(c echo.Context) string {
	if rid := strings.TrimSpace(c.Response().Header().Get(echo.HeaderXRequestID)); rid != "" {
		return rid
	}
	return strings.TrimSpace(c.Request().Header.Get(echo.HeaderXRequestID))
}

func buildAuditDetailsJSON(details map[string]any, secretID int64, opErr error) json.RawMessage {
	payload := map[string]any{}
	for key, value := range details {
		trimmedKey := strings.TrimSpace(strings.ToLower(key))
		if trimmedKey == "" {
			continue
		}
		if trimmedKey == "plain_secret" || trimmedKey == "secret_hash" || trimmedKey == "secret" {
			continue
		}
		if strings.Contains(trimmedKey, "authorization") {
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

func (h *Handler) logAndAudit(c echo.Context, action string, clientID string, secretID int64, success bool, opErr error, details map[string]any) {
	reqID := requestID(c)
	realIP := strings.TrimSpace(c.RealIP())
	actorType, actorID := admin.AdminActorFromContext(c)
	if actorType == "" {
		actorType = "unknown"
	}
	if actorID == "" {
		actorID = "unknown"
	}

	if success {
		log.Printf("admin ui action=%s actor_type=%s actor_id=%s client_id=%s secret_id=%d ip=%s request_id=%s success=true", action, actorType, actorID, clientID, secretID, realIP, reqID)
	} else {
		log.Printf("admin ui action=%s actor_type=%s actor_id=%s client_id=%s secret_id=%d ip=%s request_id=%s success=false error=%v", action, actorType, actorID, clientID, secretID, realIP, reqID, opErr)
	}

	if h.auditStore == nil {
		return
	}
	entry := store.AdminAuditEntry{
		Action:       strings.TrimSpace(action),
		Success:      success,
		ActorType:    actorType,
		ActorID:      actorID,
		RemoteIP:     realIP,
		RequestID:    reqID,
		ResourceType: "oidc_client",
		ResourceID:   strings.TrimSpace(clientID),
		DetailsJSON:  buildAuditDetailsJSON(details, secretID, opErr),
	}
	if err := h.auditStore.CreateAdminAuditEntry(c.Request().Context(), entry); err != nil {
		log.Printf("admin ui audit insert failed action=%s client_id=%s request_id=%s error=%v", action, clientID, reqID, err)
	}
}

func (h *Handler) setFlash(c echo.Context, kind string, message string) {
	kind = strings.TrimSpace(kind)
	message = strings.TrimSpace(message)
	if kind == "" || message == "" {
		return
	}

	payload, err := json.Marshal(flashMessage{Kind: kind, Message: message})
	if err != nil {
		return
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	c.SetCookie(&http.Cookie{
		Name:     flashCookieName,
		Value:    encoded,
		Path:     "/admin",
		MaxAge:   30,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) popFlash(c echo.Context) *flashMessage {
	cookie, err := c.Cookie(flashCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return nil
	}

	c.SetCookie(&http.Cookie{
		Name:     flashCookieName,
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(cookie.Value))
	if err != nil {
		return nil
	}
	var flash flashMessage
	if err := json.Unmarshal(decoded, &flash); err != nil {
		return nil
	}
	flash.Kind = strings.TrimSpace(flash.Kind)
	flash.Message = strings.TrimSpace(flash.Message)
	if flash.Kind == "" || flash.Message == "" {
		return nil
	}
	return &flash
}

func resolveTemplatesDir() string {
	candidates := []string{
		filepath.Join("web", "templates", "admin"),
		filepath.Join("..", "..", "web", "templates", "admin"),
	}
	for _, candidate := range candidates {
		layoutFile := filepath.Join(candidate, "layout.html")
		if info, err := os.Stat(layoutFile); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return filepath.Join("web", "templates", "admin")
}
