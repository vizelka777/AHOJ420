package adminui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	flashCookieName       = "admin_ui_flash"
	auditLogPageSize      = 25
	usersPageSize         = 25
	userTimelinePageSize  = 20
	userTimelineMaxSize   = 100
	defaultInviteTTLHours = 24
	dashboardRecentAudit  = 20
	dashboardRecentFailed = 10
	dashboardRecentClient = 15
	dashboardPendingLimit = 15
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
	CreateAdminUser(login string, displayName string) (*store.AdminUser, error)
	GetAdminUser(id string) (*store.AdminUser, error)
	GetAdminUserByLogin(login string) (*store.AdminUser, error)
	ListAdminUsers() ([]store.AdminUser, error)
	SetAdminUserEnabled(id string, enabled bool) error
	CountEnabledAdminUsers() (int, error)
	CountEnabledAdminUsersByRole(role string) (int, error)
	SetAdminUserRole(id string, role string) error
	CountAdminCredentialsForUser(adminUserID string) (int, error)
	CountActiveAdminInvites(ctx context.Context) (int, error)
	CountExpiredUnusedAdminInvites(ctx context.Context) (int, error)
	ListActiveAdminInvites(ctx context.Context, limit int) ([]store.ActiveAdminInviteOverview, error)
	CreateAdminInvite(ctx context.Context, adminUserID string, createdBy string, tokenHash string, expiresAt time.Time, note string) (*store.AdminInvite, error)
	GetAdminInviteByID(ctx context.Context, inviteID int64) (*store.AdminInvite, error)
	GetActiveAdminInviteByTokenHash(ctx context.Context, tokenHash string) (*store.AdminInvite, error)
	RevokeAdminInvite(ctx context.Context, inviteID int64) error
	ListAdminInvites(ctx context.Context, adminUserID string) ([]store.AdminInvite, error)
	ListUsersForAdmin(filter store.AdminUserSupportListFilter) ([]store.AdminUserSupportListItem, error)
	GetUserProfileForAdmin(userID string) (*store.AdminUserProfile, error)
	ListCredentialRecords(userID string) ([]store.CredentialRecord, error)
	DeleteCredentialByUserAndID(userID string, credID []byte) error
	ListUserOIDCClients(userID string) ([]store.UserOIDCClient, error)
}

type OIDCClientReloader interface {
	ReloadClients(ctx context.Context) error
}

type AdminAuditStore interface {
	CreateAdminAuditEntry(ctx context.Context, entry store.AdminAuditEntry) error
	ListAdminAuditEntries(ctx context.Context, opts store.AdminAuditListOptions) ([]store.AdminAuditEntry, error)
	CountAdminAuditFailuresSince(ctx context.Context, since time.Time) (int, error)
}

type SessionAuth interface {
	SessionUser(c echo.Context) (*store.AdminUser, bool)
	LogoutSession(c echo.Context) error
	ListPasskeys(c echo.Context) ([]store.AdminCredentialInfo, error)
	DeletePasskey(c echo.Context, credentialID int64) error
	ReauthMaxAge() time.Duration
	HasRecentReauth(c echo.Context, maxAge time.Duration) bool
	CurrentSessionID(c echo.Context) (string, bool)
	ListSessions(c echo.Context) ([]store.AdminSessionInfo, error)
	LogoutSessionByID(c echo.Context, sessionID string) error
	LogoutOtherSessions(c echo.Context) (int, error)
	InvalidateSessionsForAdminUser(ctx context.Context, adminUserID string) (int, error)
	CountActiveUserSessionsByUserIDs(ctx context.Context, userIDs []string) (map[string]int, error)
	ListUserSessionsForAdmin(ctx context.Context, userID string) ([]store.UserSessionInfo, error)
	LogoutUserSessionForAdmin(ctx context.Context, userID string, sessionID string) error
	LogoutAllUserSessionsForAdmin(ctx context.Context, userID string) (int, error)
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
	Title            string
	Admin            *store.AdminUser
	IsOwner          bool
	Flash            *flashMessage
	CSRFToken        string
	ReauthTTLSeconds int
}

type dashboardSummary struct {
	AdminsTotal            int
	AdminsEnabled          int
	OwnersCount            int
	AdminsRoleCount        int
	ActiveInvites          int
	ExpiredUnusedInvites   int
	ClientsTotal           int
	ClientsEnabled         int
	ClientsDisabled        int
	ClientsConfidential    int
	ClientsPublic          int
	RecentFailures24hCount int
}

type dashboardAuditPreviewItem struct {
	CreatedAt    time.Time
	Action       string
	Success      bool
	Actor        string
	ResourceType string
	ResourceID   string
	RequestID    string
	AuditURL     string
}

type dashboardPendingInviteItem struct {
	ID             int64
	AdminUserID    string
	AdminLogin     string
	CreatedBy      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	ExpiringSoon   bool
	Note           string
	AdminDetailURL string
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
	Summary             dashboardSummary
	RecentAudit         []dashboardAuditPreviewItem
	RecentFailures      []dashboardAuditPreviewItem
	RecentClientChanges []dashboardAuditPreviewItem
	PendingInvites      []dashboardPendingInviteItem
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
	ClientID        string
	Confidential    bool
	OriginalEnabled bool
	Form            clientFormData
	Error           string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	RedirectCount   int
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

type adminPasskeyView struct {
	ID            int64
	CredentialID  string
	CredentialTag string
	CreatedAt     time.Time
	LastUsedAt    *time.Time
	Transports    []string
}

type adminSessionView struct {
	SessionID  string
	SessionTag string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RemoteIP   string
	UserAgent  string
	Current    bool
}

type securityPageData struct {
	layoutData
	Passkeys []adminPasskeyView
	Sessions []adminSessionView
	Error    string
}

type adminUserListItem struct {
	ID                string
	Login             string
	DisplayName       string
	Enabled           bool
	Role              string
	CreatedAt         time.Time
	CredentialCount   int
	ActiveInviteCount int
}

type adminsListPageData struct {
	layoutData
	Admins []adminUserListItem
	Error  string
}

type adminNewPageData struct {
	layoutData
	Login          string
	DisplayName    string
	InviteNote     string
	InviteTTLHours int
	Error          string
}

type adminInviteCreatedPageData struct {
	layoutData
	Admin      *store.AdminUser
	InviteID   int64
	InviteNote string
	ExpiresAt  time.Time
	InviteURL  string
	Token      string
}

type adminInviteView struct {
	ID        int64
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	Note      string
	Status    string
}

type adminDetailPageData struct {
	layoutData
	TargetAdmin           *store.AdminUser
	CredentialCount       int
	ActiveInviteCount     int
	Invites               []adminInviteView
	RoleOptions           []string
	DefaultInviteNote     string
	DefaultInviteTTLHours int
	Error                 string
}

type userListItem struct {
	ID                   string
	LoginID              string
	ProfileEmail         string
	Phone                string
	CreatedAt            time.Time
	ProfileEmailVerified bool
	PhoneVerified        bool
	PasskeyCount         int
	SessionCount         int
	LinkedClientCount    int
}

type usersListPageData struct {
	layoutData
	Query   string
	Page    int
	PrevURL string
	NextURL string
	Users   []userListItem
	Error   string
}

type userPasskeyView struct {
	CredentialID string
	Label        string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

type userSessionView struct {
	SessionID  string
	SessionTag string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RemoteIP   string
	UserAgent  string
}

type userClientView struct {
	ClientID    string
	ClientHost  string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

type userSecurityEvent struct {
	Time        time.Time
	Type        string
	Category    string
	Success     *bool
	ActorType   string
	ActorID     string
	Description string
	ResourceID  string
	Details     map[string]any
}

type userSecurityEventView struct {
	Time     time.Time
	Type     string
	Category string
	Label    string
	Status   string
	Actor    string
	Details  string
}

type userTimelineFilterLink struct {
	Value  string
	Label  string
	URL    string
	Active bool
}

type userDetailPageData struct {
	layoutData
	User          *store.AdminUserProfile
	Passkeys      []userPasskeyView
	Sessions      []userSessionView
	LinkedClients []userClientView
	Events        []userSecurityEventView
	EventsFilter  string
	EventFilters  []userTimelineFilterLink
	Error         string
}

type inviteAcceptPageData struct {
	layoutData
	InviteToken string
	AdminLogin  string
	DisplayName string
	ExpiresAt   time.Time
}

type inviteInvalidPageData struct {
	layoutData
	Error string
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
	group.GET("/invite", handler.InviteAcceptPage)
	group.GET("/invite/:token", handler.InviteAcceptPage)
}

func RegisterProtectedRoutes(group *echo.Group, handler *Handler) {
	group.GET("/", handler.Dashboard)
	group.GET("/audit", handler.AuditLog)
	group.GET("/security", handler.SecurityPage)
	group.GET("/users", handler.UsersList)
	group.GET("/users/:id", handler.UserDetail)
	group.POST("/users/:id/sessions/logout-all", handler.UserSessionsLogoutAll)
	group.POST("/users/:id/sessions/:sessionID/logout", handler.UserSessionLogout)
	group.POST("/users/:id/passkeys/:credentialID/revoke", handler.UserPasskeyRevoke)
	group.GET("/admins", handler.AdminsList)
	group.GET("/admins/new", handler.AdminNew)
	group.POST("/admins/new", handler.AdminCreate)
	group.GET("/admins/:id", handler.AdminDetail)
	group.POST("/admins/:id/invites", handler.AdminInviteCreate)
	group.POST("/admins/:id/invites/:inviteID/revoke", handler.AdminInviteRevoke)
	group.POST("/admins/:id/disable", handler.AdminDisable)
	group.POST("/admins/:id/enable", handler.AdminEnable)
	group.POST("/admins/:id/role", handler.AdminRoleUpdate)
	group.POST("/logout", handler.Logout)
	group.POST("/security/passkeys/:id/delete", handler.SecurityPasskeyDelete)
	group.POST("/security/sessions/:id/logout", handler.SecuritySessionLogout)
	group.POST("/security/sessions/logout-others", handler.SecuritySessionsLogoutOthers)
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

func (h *Handler) SecurityPage(c echo.Context) error {
	if strings.TrimSpace(c.QueryParam("passkey_added")) == "1" {
		h.setFlash(c, "success", "Passkey added")
		return c.Redirect(http.StatusSeeOther, "/admin/security")
	}

	adminUser := h.currentAdmin(c)
	passkeys, err := h.auth.ListPasskeys(c)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "security.html", securityPageData{
			layoutData: h.newLayoutData(c, adminUser, "Admin Security"),
			Error:      "Failed to load passkeys",
		})
	}

	sessions, err := h.auth.ListSessions(c)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "security.html", securityPageData{
			layoutData: h.newLayoutData(c, adminUser, "Admin Security"),
			Passkeys:   buildPasskeyViews(passkeys),
			Error:      "Failed to load sessions",
		})
	}

	return h.render(c, http.StatusOK, "security.html", securityPageData{
		layoutData: h.newLayoutData(c, adminUser, "Admin Security"),
		Passkeys:   buildPasskeyViews(passkeys),
		Sessions:   buildSessionViews(sessions),
	})
}

func (h *Handler) SecurityPasskeyDelete(c echo.Context) error {
	if err := h.requireRecentReauth(c); err != nil {
		return err
	}

	credentialID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || credentialID <= 0 {
		h.setFlash(c, "error", "Invalid passkey ID")
		return c.Redirect(http.StatusSeeOther, "/admin/security")
	}

	if err := h.auth.DeletePasskey(c, credentialID); err != nil {
		switch {
		case errors.Is(err, store.ErrAdminCredentialLast):
			h.setFlash(c, "error", "Cannot delete the last passkey")
		case errors.Is(err, store.ErrAdminCredentialNotFound):
			h.setFlash(c, "error", "Passkey not found")
		default:
			h.setFlash(c, "error", "Failed to delete passkey")
		}
		return c.Redirect(http.StatusSeeOther, "/admin/security")
	}

	h.setFlash(c, "success", "Passkey deleted")
	return c.Redirect(http.StatusSeeOther, "/admin/security")
}

func (h *Handler) SecuritySessionLogout(c echo.Context) error {
	sessionID := strings.TrimSpace(c.Param("id"))
	if sessionID == "" {
		h.setFlash(c, "error", "Invalid session ID")
		return c.Redirect(http.StatusSeeOther, "/admin/security")
	}

	currentSessionID, _ := h.auth.CurrentSessionID(c)
	if sessionID != currentSessionID {
		if err := h.requireRecentReauth(c); err != nil {
			return err
		}
	}

	if err := h.auth.LogoutSessionByID(c, sessionID); err != nil {
		h.setFlash(c, "error", "Failed to sign out session")
		return c.Redirect(http.StatusSeeOther, "/admin/security")
	}

	if sessionID == currentSessionID {
		h.clearCSRFCookie(c)
		h.setFlash(c, "success", "Signed out current session")
		return c.Redirect(http.StatusSeeOther, "/admin/login")
	}

	h.setFlash(c, "success", "Session signed out")
	return c.Redirect(http.StatusSeeOther, "/admin/security")
}

func (h *Handler) SecuritySessionsLogoutOthers(c echo.Context) error {
	if err := h.requireRecentReauth(c); err != nil {
		return err
	}

	removed, err := h.auth.LogoutOtherSessions(c)
	if err != nil {
		h.setFlash(c, "error", "Failed to sign out other sessions")
		return c.Redirect(http.StatusSeeOther, "/admin/security")
	}

	if removed == 0 {
		h.setFlash(c, "success", "No other sessions to sign out")
	} else {
		h.setFlash(c, "success", fmt.Sprintf("Signed out %d other session(s)", removed))
	}
	return c.Redirect(http.StatusSeeOther, "/admin/security")
}

func (h *Handler) UsersList(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	query := strings.TrimSpace(c.QueryParam("q"))
	page := parseListPage(c.QueryParam("page"))

	rows, err := h.store.ListUsersForAdmin(store.AdminUserSupportListFilter{
		Query:  query,
		Limit:  usersPageSize + 1,
		Offset: (page - 1) * usersPageSize,
	})
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "users_list.html", usersListPageData{
			layoutData: h.newLayoutData(c, adminUser, "Users"),
			Query:      query,
			Page:       page,
			Error:      "Failed to load users",
		})
	}

	hasNext := len(rows) > usersPageSize
	if hasNext {
		rows = rows[:usersPageSize]
	}

	userIDs := make([]string, 0, len(rows))
	for _, item := range rows {
		if strings.TrimSpace(item.ID) == "" {
			continue
		}
		userIDs = append(userIDs, strings.TrimSpace(item.ID))
	}
	sessionCounts, err := h.auth.CountActiveUserSessionsByUserIDs(c.Request().Context(), userIDs)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "users_list.html", usersListPageData{
			layoutData: h.newLayoutData(c, adminUser, "Users"),
			Query:      query,
			Page:       page,
			Error:      "Failed to load user sessions",
		})
	}

	items := make([]userListItem, 0, len(rows))
	for _, item := range rows {
		id := strings.TrimSpace(item.ID)
		items = append(items, userListItem{
			ID:                   id,
			LoginID:              strings.TrimSpace(item.LoginID),
			ProfileEmail:         strings.TrimSpace(item.ProfileEmail),
			Phone:                strings.TrimSpace(item.Phone),
			CreatedAt:            item.CreatedAt,
			ProfileEmailVerified: item.ProfileEmailVerified,
			PhoneVerified:        item.PhoneVerified,
			PasskeyCount:         item.PasskeyCount,
			SessionCount:         sessionCounts[id],
			LinkedClientCount:    item.LinkedClientCount,
		})
	}

	prevURL := ""
	if page > 1 {
		prevURL = usersListURL(page-1, query)
	}
	nextURL := ""
	if hasNext {
		nextURL = usersListURL(page+1, query)
	}

	return h.render(c, http.StatusOK, "users_list.html", usersListPageData{
		layoutData: h.newLayoutData(c, adminUser, "Users"),
		Query:      query,
		Page:       page,
		PrevURL:    prevURL,
		NextURL:    nextURL,
		Users:      items,
	})
}

func (h *Handler) UserDetail(c echo.Context) error {
	adminUser := h.currentAdmin(c)
	userID := strings.TrimSpace(c.Param("id"))
	eventsFilter := parseUserEventsFilter(c.QueryParam("events"))
	eventFilters := buildUserTimelineFilterLinks(userID, eventsFilter)
	if userID == "" {
		return h.render(c, http.StatusBadRequest, "user_detail.html", userDetailPageData{
			layoutData:   h.newLayoutData(c, adminUser, "User"),
			EventsFilter: eventsFilter,
			EventFilters: eventFilters,
			Error:        "User ID is required",
		})
	}

	profile, err := h.store.GetUserProfileForAdmin(userID)
	if err != nil {
		status := http.StatusInternalServerError
		message := "Failed to load user profile"
		if errors.Is(err, store.ErrUserNotFound) {
			status = http.StatusNotFound
			message = "User not found"
		}
		return h.render(c, status, "user_detail.html", userDetailPageData{
			layoutData:   h.newLayoutData(c, adminUser, "User"),
			EventsFilter: eventsFilter,
			EventFilters: eventFilters,
			Error:        message,
		})
	}

	passkeysRaw, err := h.store.ListCredentialRecords(userID)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "user_detail.html", userDetailPageData{
			layoutData:   h.newLayoutData(c, adminUser, "User: "+profile.ID),
			User:         profile,
			EventsFilter: eventsFilter,
			EventFilters: eventFilters,
			Error:        "Failed to load user passkeys",
		})
	}

	sessionsRaw, err := h.auth.ListUserSessionsForAdmin(c.Request().Context(), userID)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "user_detail.html", userDetailPageData{
			layoutData:   h.newLayoutData(c, adminUser, "User: "+profile.ID),
			User:         profile,
			Passkeys:     buildUserPasskeyViews(passkeysRaw),
			EventsFilter: eventsFilter,
			EventFilters: eventFilters,
			Error:        "Failed to load user sessions",
		})
	}

	linkedClientsRaw, err := h.store.ListUserOIDCClients(userID)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "user_detail.html", userDetailPageData{
			layoutData:   h.newLayoutData(c, adminUser, "User: "+profile.ID),
			User:         profile,
			Passkeys:     buildUserPasskeyViews(passkeysRaw),
			Sessions:     buildUserSessionViews(sessionsRaw),
			EventsFilter: eventsFilter,
			EventFilters: eventFilters,
			Error:        "Failed to load linked clients",
		})
	}

	events, err := h.listUserSecurityEvents(c.Request().Context(), userID, eventsFilter, userTimelinePageSize, passkeysRaw, sessionsRaw, linkedClientsRaw)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "user_detail.html", userDetailPageData{
			layoutData:    h.newLayoutData(c, adminUser, "User: "+profile.ID),
			User:          profile,
			Passkeys:      buildUserPasskeyViews(passkeysRaw),
			Sessions:      buildUserSessionViews(sessionsRaw),
			LinkedClients: buildUserClientViews(linkedClientsRaw),
			EventsFilter:  eventsFilter,
			EventFilters:  eventFilters,
			Error:         "Failed to load user security events",
		})
	}

	return h.render(c, http.StatusOK, "user_detail.html", userDetailPageData{
		layoutData:    h.newLayoutData(c, adminUser, "User: "+profile.ID),
		User:          profile,
		Passkeys:      buildUserPasskeyViews(passkeysRaw),
		Sessions:      buildUserSessionViews(sessionsRaw),
		LinkedClients: buildUserClientViews(linkedClientsRaw),
		Events:        events,
		EventsFilter:  eventsFilter,
		EventFilters:  eventFilters,
	})
}

func (h *Handler) UserSessionLogout(c echo.Context) error {
	userID := strings.TrimSpace(c.Param("id"))
	sessionID := strings.TrimSpace(c.Param("sessionID"))
	if userID == "" {
		h.setFlash(c, "error", "Invalid user ID")
		return c.Redirect(http.StatusSeeOther, "/admin/users")
	}
	if sessionID == "" {
		h.setFlash(c, "error", "Invalid session ID")
		return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
	}

	if err := h.auth.LogoutUserSessionForAdmin(c.Request().Context(), userID, sessionID); err != nil {
		h.auditAdminAction(c, "admin.user.session.logout.failure", false, "user_session", sessionID, err, map[string]any{
			"user_id": userID,
		})
		h.setFlash(c, "error", "Failed to sign out user session")
		return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
	}

	h.auditAdminAction(c, "admin.user.session.logout.success", true, "user_session", sessionID, nil, map[string]any{
		"user_id": userID,
	})
	h.setFlash(c, "success", "User session signed out")
	return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
}

func (h *Handler) UserSessionsLogoutAll(c echo.Context) error {
	if err := h.requireRecentReauth(c); err != nil {
		return err
	}

	userID := strings.TrimSpace(c.Param("id"))
	if userID == "" {
		h.setFlash(c, "error", "Invalid user ID")
		return c.Redirect(http.StatusSeeOther, "/admin/users")
	}

	removed, err := h.auth.LogoutAllUserSessionsForAdmin(c.Request().Context(), userID)
	if err != nil {
		h.auditAdminAction(c, "admin.user.session.logout_all.failure", false, "user", userID, err, map[string]any{
			"recent_reauth": true,
		})
		h.setFlash(c, "error", "Failed to sign out all user sessions")
		return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
	}

	h.auditAdminAction(c, "admin.user.session.logout_all.success", true, "user", userID, nil, map[string]any{
		"recent_reauth": true,
		"removed_count": removed,
	})
	if removed == 0 {
		h.setFlash(c, "success", "No active user sessions to sign out")
	} else {
		h.setFlash(c, "success", fmt.Sprintf("Signed out %d user session(s)", removed))
	}
	return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
}

func (h *Handler) UserPasskeyRevoke(c echo.Context) error {
	if err := h.requireRecentReauth(c); err != nil {
		return err
	}

	userID := strings.TrimSpace(c.Param("id"))
	credentialID := strings.TrimSpace(c.Param("credentialID"))
	if userID == "" {
		h.setFlash(c, "error", "Invalid user ID")
		return c.Redirect(http.StatusSeeOther, "/admin/users")
	}
	if credentialID == "" {
		h.setFlash(c, "error", "Invalid passkey ID")
		return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
	}
	credentialRaw, err := hex.DecodeString(credentialID)
	if err != nil || len(credentialRaw) == 0 {
		h.setFlash(c, "error", "Invalid passkey ID")
		return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
	}

	if err := h.store.DeleteCredentialByUserAndID(userID, credentialRaw); err != nil {
		h.auditAdminAction(c, "admin.user.passkey.revoke.failure", false, "user_credential", credentialID, err, map[string]any{
			"user_id":       userID,
			"recent_reauth": true,
		})
		switch {
		case errors.Is(err, store.ErrCredentialNotFound):
			h.setFlash(c, "error", "Passkey not found")
		case errors.Is(err, store.ErrCannotDeleteLastCredential):
			h.setFlash(c, "error", "Cannot revoke the last passkey")
		default:
			h.setFlash(c, "error", "Failed to revoke passkey")
		}
		return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
	}

	h.auditAdminAction(c, "admin.user.passkey.revoke.success", true, "user_credential", credentialID, nil, map[string]any{
		"user_id":       userID,
		"recent_reauth": true,
	})
	h.setFlash(c, "success", "User passkey revoked")
	return c.Redirect(http.StatusSeeOther, "/admin/users/"+userID)
}

func (h *Handler) listUserSecurityEvents(ctx context.Context, userID string, category string, limit int, passkeys []store.CredentialRecord, sessions []store.UserSessionInfo, linkedClients []store.UserOIDCClient) ([]userSecurityEventView, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []userSecurityEventView{}, nil
	}

	if limit <= 0 {
		limit = userTimelinePageSize
	}
	if limit > userTimelineMaxSize {
		limit = userTimelineMaxSize
	}

	auditLimit := limit * 5
	if auditLimit < 100 {
		auditLimit = 100
	}
	if auditLimit > 200 {
		auditLimit = 200
	}
	adminAuditEntries, err := h.auditStore.ListAdminAuditEntries(ctx, store.AdminAuditListOptions{
		Limit:  auditLimit,
		Offset: 0,
		Action: "admin.user.",
	})
	if err != nil {
		return nil, err
	}

	events := make([]userSecurityEvent, 0, len(adminAuditEntries)+len(passkeys)*2+len(sessions)*2+len(linkedClients)*2)
	events = append(events, buildUserSecurityEventsFromAdminAudit(adminAuditEntries, userID)...)
	events = append(events, buildUserSecurityEventsFromPasskeys(userID, passkeys)...)
	events = append(events, buildUserSecurityEventsFromSessions(userID, sessions)...)
	events = append(events, buildUserSecurityEventsFromLinkedClients(userID, linkedClients)...)
	events = filterUserSecurityEventsByCategory(events, category)

	sort.Slice(events, func(i, j int) bool {
		left := events[i]
		right := events[j]
		if left.Time.Equal(right.Time) {
			return left.Type < right.Type
		}
		return left.Time.After(right.Time)
	})
	if len(events) > limit {
		events = events[:limit]
	}

	out := make([]userSecurityEventView, 0, len(events))
	for _, event := range events {
		out = append(out, userSecurityEventView{
			Time:     event.Time,
			Type:     event.Type,
			Category: event.Category,
			Label:    strings.TrimSpace(event.Description),
			Status:   userSecurityEventStatus(event.Success),
			Actor:    formatUserSecurityActor(event, userID),
			Details:  formatUserSecurityEventDetails(event.Details),
		})
	}
	return out, nil
}

func buildUserSecurityEventsFromAdminAudit(entries []store.AdminAuditEntry, userID string) []userSecurityEvent {
	out := make([]userSecurityEvent, 0, len(entries))
	for _, entry := range entries {
		details := decodeUserSecurityAuditDetails(entry.DetailsJSON)
		if !adminAuditEntryBelongsToUser(entry, userID, details) {
			continue
		}

		action := strings.TrimSpace(entry.Action)
		var (
			eventType   string
			description string
		)
		switch action {
		case "admin.user.session.logout.success", "admin.user.session.logout.failure":
			eventType = "admin_session_logout"
			description = "Admin logged out user session"
		case "admin.user.session.logout_all.success", "admin.user.session.logout_all.failure":
			eventType = "admin_session_logout_all"
			description = "Admin logged out all user sessions"
		case "admin.user.passkey.revoke.success", "admin.user.passkey.revoke.failure":
			eventType = "admin_passkey_revoke"
			description = "Admin revoked user passkey"
		default:
			if !strings.HasPrefix(action, "admin.user.") {
				continue
			}
			eventType = strings.ReplaceAll(strings.TrimPrefix(action, "admin."), ".", "_")
			description = "Admin support action"
		}

		success := entry.Success
		out = append(out, userSecurityEvent{
			Time:        entry.CreatedAt,
			Type:        eventType,
			Category:    "admin",
			Success:     &success,
			ActorType:   strings.TrimSpace(entry.ActorType),
			ActorID:     strings.TrimSpace(entry.ActorID),
			Description: description,
			ResourceID:  strings.TrimSpace(entry.ResourceID),
			Details:     normalizeUserSecurityEventDetails(details),
		})
	}
	return out
}

func buildUserSecurityEventsFromPasskeys(userID string, passkeys []store.CredentialRecord) []userSecurityEvent {
	out := make([]userSecurityEvent, 0, len(passkeys)*2)
	for _, item := range passkeys {
		credentialID := hex.EncodeToString(item.ID)
		credentialTag := shortDisplay(credentialID, 12, 8)
		out = append(out, userSecurityEvent{
			Time:        item.CreatedAt,
			Type:        "passkey_added",
			Category:    "passkeys",
			Success:     boolPtr(true),
			ActorType:   "user",
			ActorID:     userID,
			Description: "Passkey registered",
			ResourceID:  credentialID,
			Details: map[string]any{
				"credential": credentialTag,
			},
		})
		if item.LastUsedAt != nil && !item.LastUsedAt.IsZero() {
			out = append(out, userSecurityEvent{
				Time:        item.LastUsedAt.UTC(),
				Type:        "passkey_used",
				Category:    "auth",
				Success:     boolPtr(true),
				ActorType:   "user",
				ActorID:     userID,
				Description: "Passkey used for authentication",
				ResourceID:  credentialID,
				Details: map[string]any{
					"credential": credentialTag,
				},
			})
		}
	}
	return out
}

func buildUserSecurityEventsFromSessions(userID string, sessions []store.UserSessionInfo) []userSecurityEvent {
	out := make([]userSecurityEvent, 0, len(sessions)*2)
	for _, item := range sessions {
		sessionID := strings.TrimSpace(item.SessionID)
		sessionTag := shortDisplay(sessionID, 10, 8)
		details := map[string]any{
			"session": sessionTag,
		}
		if strings.TrimSpace(item.RemoteIP) != "" {
			details["remote_ip"] = strings.TrimSpace(item.RemoteIP)
		}

		if !item.CreatedAt.IsZero() {
			out = append(out, userSecurityEvent{
				Time:        item.CreatedAt,
				Type:        "session_started",
				Category:    "sessions",
				Success:     boolPtr(true),
				ActorType:   "user",
				ActorID:     userID,
				Description: "Session started",
				ResourceID:  sessionID,
				Details:     details,
			})
		}
		if !item.LastSeenAt.IsZero() && !item.LastSeenAt.Equal(item.CreatedAt) {
			out = append(out, userSecurityEvent{
				Time:        item.LastSeenAt,
				Type:        "session_activity",
				Category:    "sessions",
				Success:     nil,
				ActorType:   "user",
				ActorID:     userID,
				Description: "Session activity observed",
				ResourceID:  sessionID,
				Details:     details,
			})
		}
	}
	return out
}

func buildUserSecurityEventsFromLinkedClients(userID string, linkedClients []store.UserOIDCClient) []userSecurityEvent {
	out := make([]userSecurityEvent, 0, len(linkedClients)*2)
	for _, item := range linkedClients {
		clientID := strings.TrimSpace(item.ClientID)
		if clientID == "" {
			continue
		}
		details := map[string]any{
			"client_id": clientID,
		}
		if host := strings.TrimSpace(item.ClientHost); host != "" {
			details["client_host"] = host
		}
		if !item.FirstSeenAt.IsZero() {
			out = append(out, userSecurityEvent{
				Time:        item.FirstSeenAt,
				Type:        "client_linked",
				Category:    "auth",
				Success:     boolPtr(true),
				ActorType:   "user",
				ActorID:     userID,
				Description: "OIDC client linked to user",
				ResourceID:  clientID,
				Details:     details,
			})
		}
		if !item.LastSeenAt.IsZero() && !item.LastSeenAt.Equal(item.FirstSeenAt) {
			out = append(out, userSecurityEvent{
				Time:        item.LastSeenAt,
				Type:        "client_activity",
				Category:    "auth",
				Success:     nil,
				ActorType:   "user",
				ActorID:     userID,
				Description: "OIDC client activity observed",
				ResourceID:  clientID,
				Details:     details,
			})
		}
	}
	return out
}

func decodeUserSecurityAuditDetails(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return map[string]any{}
	}
	sanitized := sanitizeAuditDetails(decoded)
	asMap, ok := sanitized.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return asMap
}

func adminAuditEntryBelongsToUser(entry store.AdminAuditEntry, userID string, details map[string]any) bool {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return false
	}
	if strings.TrimSpace(entry.ResourceID) == userID {
		return true
	}
	if detailUserID := strings.TrimSpace(anyString(details["user_id"])); detailUserID == userID {
		return true
	}
	return false
}

func normalizeUserSecurityEventDetails(details map[string]any) map[string]any {
	if len(details) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(details))
	for key, value := range details {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" || normalized == "user_id" || normalized == "recent_reauth" {
			continue
		}
		out[normalized] = sanitizeAuditDetails(value)
	}
	return out
}

func filterUserSecurityEventsByCategory(events []userSecurityEvent, category string) []userSecurityEvent {
	category = parseUserEventsFilter(category)
	if category == "all" {
		return append([]userSecurityEvent(nil), events...)
	}
	out := make([]userSecurityEvent, 0, len(events))
	for _, event := range events {
		if strings.TrimSpace(event.Category) != category {
			continue
		}
		out = append(out, event)
	}
	return out
}

func userSecurityEventStatus(success *bool) string {
	if success == nil {
		return "info"
	}
	if *success {
		return "success"
	}
	return "failure"
}

func formatUserSecurityActor(event userSecurityEvent, userID string) string {
	actorType := strings.TrimSpace(event.ActorType)
	actorID := strings.TrimSpace(event.ActorID)
	switch actorType {
	case "user":
		if actorID == "" || actorID == userID {
			return "user"
		}
		return "user:" + actorID
	case "system":
		if actorID == "" {
			return "system"
		}
		return "system:" + actorID
	default:
		return formatAuditActor(actorType, actorID)
	}
}

func formatUserSecurityEventDetails(details map[string]any) string {
	if len(details) == 0 {
		return "-"
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return "-"
	}
	trimmed := strings.TrimSpace(string(encoded))
	if trimmed == "" || trimmed == "{}" || trimmed == "[]" || trimmed == "null" {
		return "-"
	}
	if len(trimmed) > 220 {
		return trimmed[:217] + "..."
	}
	return trimmed
}

func anyString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		rendered := strings.TrimSpace(fmt.Sprintf("%v", typed))
		if rendered == "<nil>" {
			return ""
		}
		return rendered
	}
}

func boolPtr(value bool) *bool {
	item := value
	return &item
}

func (h *Handler) InviteAcceptPage(c echo.Context) error {
	token := strings.TrimSpace(c.Param("token"))
	if token == "" {
		token = strings.TrimSpace(c.QueryParam("token"))
	}
	if token == "" {
		return h.render(c, http.StatusBadRequest, "invite_invalid.html", inviteInvalidPageData{
			layoutData: layoutData{Title: "Admin Invite"},
			Error:      "Invite token is missing",
		})
	}

	invite, err := h.store.GetActiveAdminInviteByTokenHash(c.Request().Context(), hashInviteToken(token))
	if err != nil {
		return h.render(c, http.StatusBadRequest, "invite_invalid.html", inviteInvalidPageData{
			layoutData: layoutData{Title: "Admin Invite"},
			Error:      "Invite is invalid, expired, revoked, or already used",
		})
	}

	targetAdmin, err := h.store.GetAdminUser(invite.AdminUserID)
	if err != nil || targetAdmin == nil {
		return h.render(c, http.StatusBadRequest, "invite_invalid.html", inviteInvalidPageData{
			layoutData: layoutData{Title: "Admin Invite"},
			Error:      "Invite target admin user does not exist",
		})
	}
	if !targetAdmin.Enabled {
		return h.render(c, http.StatusForbidden, "invite_invalid.html", inviteInvalidPageData{
			layoutData: layoutData{Title: "Admin Invite"},
			Error:      "Invite target admin user is disabled",
		})
	}

	credentialCount, err := h.store.CountAdminCredentialsForUser(targetAdmin.ID)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "invite_invalid.html", inviteInvalidPageData{
			layoutData: layoutData{Title: "Admin Invite"},
			Error:      "Failed to validate invite target",
		})
	}
	if credentialCount > 0 {
		return h.render(c, http.StatusConflict, "invite_invalid.html", inviteInvalidPageData{
			layoutData: layoutData{Title: "Admin Invite"},
			Error:      "Invite can only be used for admin without passkeys",
		})
	}

	return h.render(c, http.StatusOK, "invite_accept.html", inviteAcceptPageData{
		layoutData:  layoutData{Title: "Admin Invite"},
		InviteToken: token,
		AdminLogin:  targetAdmin.Login,
		DisplayName: targetAdmin.DisplayName,
		ExpiresAt:   invite.ExpiresAt,
	})
}

func (h *Handler) AdminsList(c echo.Context) error {
	adminUser, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	admins, err := h.store.ListAdminUsers()
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "admins_list.html", adminsListPageData{
			layoutData: h.newLayoutData(c, adminUser, "Admins"),
			Error:      "Failed to load admin users",
		})
	}

	items := make([]adminUserListItem, 0, len(admins))
	for _, item := range admins {
		items = append(items, adminUserListItem{
			ID:                strings.TrimSpace(item.ID),
			Login:             strings.TrimSpace(item.Login),
			DisplayName:       strings.TrimSpace(item.DisplayName),
			Enabled:           item.Enabled,
			Role:              store.NormalizeAdminRole(item.Role),
			CreatedAt:         item.CreatedAt,
			CredentialCount:   item.CredentialCount,
			ActiveInviteCount: item.ActiveInviteCount,
		})
	}

	return h.render(c, http.StatusOK, "admins_list.html", adminsListPageData{
		layoutData: h.newLayoutData(c, adminUser, "Admins"),
		Admins:     items,
	})
}

func (h *Handler) AdminNew(c echo.Context) error {
	adminUser, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	return h.render(c, http.StatusOK, "admin_new.html", adminNewPageData{
		layoutData:     h.newLayoutData(c, adminUser, "New Admin"),
		InviteTTLHours: defaultInviteTTLHours,
	})
}

func (h *Handler) AdminCreate(c echo.Context) error {
	currentAdmin, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	createdByID := ""
	if currentAdmin != nil {
		createdByID = strings.TrimSpace(currentAdmin.ID)
	}
	if createdByID == "" {
		return c.String(http.StatusUnauthorized, "admin session is required")
	}
	login := strings.TrimSpace(c.FormValue("login"))
	displayName := strings.TrimSpace(c.FormValue("display_name"))
	inviteNote := strings.TrimSpace(c.FormValue("invite_note"))
	inviteTTLHours := parseInviteTTLHours(c.FormValue("invite_ttl_hours"), defaultInviteTTLHours)

	renderFormError := func(message string, status int) error {
		return h.render(c, status, "admin_new.html", adminNewPageData{
			layoutData:     h.newLayoutData(c, currentAdmin, "New Admin"),
			Login:          login,
			DisplayName:    displayName,
			InviteNote:     inviteNote,
			InviteTTLHours: inviteTTLHours,
			Error:          strings.TrimSpace(message),
		})
	}

	if login == "" {
		return renderFormError("Login is required", http.StatusBadRequest)
	}
	if _, err := h.store.GetAdminUserByLogin(login); err == nil {
		return renderFormError("Admin login already exists", http.StatusConflict)
	} else if !errors.Is(err, store.ErrAdminUserNotFound) {
		return renderFormError("Failed to validate admin login uniqueness", http.StatusInternalServerError)
	}

	targetAdmin, err := h.store.CreateAdminUser(login, displayName)
	if err != nil {
		h.auditAdminAction(c, "admin.user.create.failure", false, "admin_user", "", err, map[string]any{
			"login": login,
		})
		return renderFormError("Failed to create admin user", http.StatusInternalServerError)
	}
	h.auditAdminAction(c, "admin.user.create.success", true, "admin_user", targetAdmin.ID, nil, map[string]any{
		"login":        targetAdmin.Login,
		"display_name": targetAdmin.DisplayName,
	})

	token, err := newInviteToken()
	if err != nil {
		h.auditAdminAction(c, "admin.invite.create.failure", false, "admin_invite", "", err, map[string]any{
			"admin_user_id": targetAdmin.ID,
		})
		return renderFormError("Admin created, but failed to generate invite token", http.StatusInternalServerError)
	}
	expiresAt := time.Now().UTC().Add(time.Duration(inviteTTLHours) * time.Hour)
	invite, err := h.store.CreateAdminInvite(c.Request().Context(), targetAdmin.ID, createdByID, hashInviteToken(token), expiresAt, inviteNote)
	if err != nil {
		h.auditAdminAction(c, "admin.invite.create.failure", false, "admin_invite", "", err, map[string]any{
			"admin_user_id": targetAdmin.ID,
			"expires_at":    expiresAt.Format(time.RFC3339),
		})
		return renderFormError("Admin created, but failed to create invite", http.StatusInternalServerError)
	}

	h.auditAdminAction(c, "admin.invite.create.success", true, "admin_invite", strconv.FormatInt(invite.ID, 10), nil, map[string]any{
		"admin_user_id": targetAdmin.ID,
		"expires_at":    invite.ExpiresAt.Format(time.RFC3339),
		"note":          invite.Note,
	})

	return h.render(c, http.StatusCreated, "admin_invite_created.html", adminInviteCreatedPageData{
		layoutData: h.newLayoutData(c, currentAdmin, "Admin Invite Created"),
		Admin:      targetAdmin,
		InviteID:   invite.ID,
		InviteNote: invite.Note,
		ExpiresAt:  invite.ExpiresAt,
		InviteURL:  buildInviteURL(c, token),
		Token:      token,
	})
}

func (h *Handler) AdminDetail(c echo.Context) error {
	currentAdmin, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	targetAdminID := strings.TrimSpace(c.Param("id"))
	if targetAdminID == "" {
		return h.render(c, http.StatusBadRequest, "admin_detail.html", adminDetailPageData{
			layoutData: h.newLayoutData(c, currentAdmin, "Admin"),
			Error:      "Admin user ID is required",
		})
	}

	targetAdmin, err := h.store.GetAdminUser(targetAdminID)
	if err != nil {
		status := http.StatusInternalServerError
		message := "Failed to load admin user"
		if errors.Is(err, store.ErrAdminUserNotFound) {
			status = http.StatusNotFound
			message = "Admin user not found"
		}
		return h.render(c, status, "admin_detail.html", adminDetailPageData{
			layoutData: h.newLayoutData(c, currentAdmin, "Admin"),
			Error:      message,
		})
	}

	credentialCount, err := h.store.CountAdminCredentialsForUser(targetAdmin.ID)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "admin_detail.html", adminDetailPageData{
			layoutData:  h.newLayoutData(c, currentAdmin, "Admin"),
			TargetAdmin: targetAdmin,
			Error:       "Failed to load admin credentials",
		})
	}

	invitesRaw, err := h.store.ListAdminInvites(c.Request().Context(), targetAdmin.ID)
	if err != nil {
		return h.render(c, http.StatusInternalServerError, "admin_detail.html", adminDetailPageData{
			layoutData:  h.newLayoutData(c, currentAdmin, "Admin"),
			TargetAdmin: targetAdmin,
			Error:       "Failed to load admin invites",
		})
	}

	now := time.Now().UTC()
	activeInviteCount := 0
	invites := make([]adminInviteView, 0, len(invitesRaw))
	for _, invite := range invitesRaw {
		status := "active"
		switch {
		case invite.UsedAt != nil:
			status = "used"
		case invite.RevokedAt != nil:
			status = "revoked"
		case !invite.ExpiresAt.After(now):
			status = "expired"
		default:
			activeInviteCount++
		}
		invites = append(invites, adminInviteView{
			ID:        invite.ID,
			CreatedAt: invite.CreatedAt,
			ExpiresAt: invite.ExpiresAt,
			UsedAt:    invite.UsedAt,
			RevokedAt: invite.RevokedAt,
			Note:      invite.Note,
			Status:    status,
		})
	}

	return h.render(c, http.StatusOK, "admin_detail.html", adminDetailPageData{
		layoutData:            h.newLayoutData(c, currentAdmin, "Admin: "+targetAdmin.Login),
		TargetAdmin:           targetAdmin,
		CredentialCount:       credentialCount,
		ActiveInviteCount:     activeInviteCount,
		Invites:               invites,
		RoleOptions:           []string{store.AdminRoleAdmin, store.AdminRoleOwner},
		DefaultInviteTTLHours: defaultInviteTTLHours,
	})
}

func (h *Handler) AdminInviteCreate(c echo.Context) error {
	currentAdmin, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	createdByID := ""
	if currentAdmin != nil {
		createdByID = strings.TrimSpace(currentAdmin.ID)
	}
	if createdByID == "" {
		return c.String(http.StatusUnauthorized, "admin session is required")
	}
	targetAdminID := strings.TrimSpace(c.Param("id"))
	note := strings.TrimSpace(c.FormValue("note"))
	ttlHours := parseInviteTTLHours(c.FormValue("ttl_hours"), defaultInviteTTLHours)

	targetAdmin, err := h.store.GetAdminUser(targetAdminID)
	if err != nil {
		h.setFlash(c, "error", "Admin user not found")
		return c.Redirect(http.StatusSeeOther, "/admin/admins")
	}
	if !targetAdmin.Enabled {
		h.setFlash(c, "error", "Cannot create invite for disabled admin user")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdmin.ID)
	}

	credentialCount, err := h.store.CountAdminCredentialsForUser(targetAdmin.ID)
	if err != nil {
		h.setFlash(c, "error", "Failed to validate target admin")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdmin.ID)
	}
	if credentialCount > 0 {
		h.setFlash(c, "error", "Invite flow is for admin without passkeys")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdmin.ID)
	}

	token, err := newInviteToken()
	if err != nil {
		h.auditAdminAction(c, "admin.invite.create.failure", false, "admin_invite", "", err, map[string]any{"admin_user_id": targetAdmin.ID})
		h.setFlash(c, "error", "Failed to generate invite token")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdmin.ID)
	}
	expiresAt := time.Now().UTC().Add(time.Duration(ttlHours) * time.Hour)
	invite, err := h.store.CreateAdminInvite(c.Request().Context(), targetAdmin.ID, createdByID, hashInviteToken(token), expiresAt, note)
	if err != nil {
		h.auditAdminAction(c, "admin.invite.create.failure", false, "admin_invite", "", err, map[string]any{
			"admin_user_id": targetAdmin.ID,
			"expires_at":    expiresAt.Format(time.RFC3339),
		})
		h.setFlash(c, "error", "Failed to create invite")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdmin.ID)
	}

	h.auditAdminAction(c, "admin.invite.create.success", true, "admin_invite", strconv.FormatInt(invite.ID, 10), nil, map[string]any{
		"admin_user_id": targetAdmin.ID,
		"expires_at":    invite.ExpiresAt.Format(time.RFC3339),
		"note":          invite.Note,
	})

	return h.render(c, http.StatusCreated, "admin_invite_created.html", adminInviteCreatedPageData{
		layoutData: h.newLayoutData(c, currentAdmin, "Admin Invite Created"),
		Admin:      targetAdmin,
		InviteID:   invite.ID,
		InviteNote: invite.Note,
		ExpiresAt:  invite.ExpiresAt,
		InviteURL:  buildInviteURL(c, token),
		Token:      token,
	})
}

func (h *Handler) AdminInviteRevoke(c echo.Context) error {
	currentAdmin, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	targetAdminID := strings.TrimSpace(c.Param("id"))
	inviteID, err := strconv.ParseInt(strings.TrimSpace(c.Param("inviteID")), 10, 64)
	if err != nil || inviteID <= 0 {
		h.setFlash(c, "error", "Invalid invite ID")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	invite, err := h.store.GetAdminInviteByID(c.Request().Context(), inviteID)
	if err != nil || strings.TrimSpace(invite.AdminUserID) != targetAdminID {
		h.auditAdminAction(c, "admin.invite.revoke.failure", false, "admin_invite", strconv.FormatInt(inviteID, 10), err, map[string]any{
			"admin_user_id": targetAdminID,
		})
		h.setFlash(c, "error", "Invite not found")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	if err := h.store.RevokeAdminInvite(c.Request().Context(), inviteID); err != nil {
		h.auditAdminAction(c, "admin.invite.revoke.failure", false, "admin_invite", strconv.FormatInt(inviteID, 10), err, map[string]any{
			"admin_user_id": targetAdminID,
		})
		h.setFlash(c, "error", "Invite cannot be revoked")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	h.auditAdminAction(c, "admin.invite.revoke.success", true, "admin_invite", strconv.FormatInt(inviteID, 10), nil, map[string]any{
		"admin_user_id": targetAdminID,
		"actor_role":    store.NormalizeAdminRole(currentAdmin.Role),
	})
	h.setFlash(c, "success", "Invite revoked")
	return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
}

func (h *Handler) AdminDisable(c echo.Context) error {
	currentAdmin, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	targetAdminID := strings.TrimSpace(c.Param("id"))
	if targetAdminID == "" {
		h.setFlash(c, "error", "Invalid admin user ID")
		return c.Redirect(http.StatusSeeOther, "/admin/admins")
	}

	if currentAdmin != nil && strings.TrimSpace(currentAdmin.ID) == targetAdminID {
		h.setFlash(c, "error", "Self-disable is blocked")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	targetAdmin, err := h.store.GetAdminUser(targetAdminID)
	if err != nil {
		h.auditAdminAction(c, "admin.user.disable.failure", false, "admin_user", targetAdminID, err, nil)
		h.setFlash(c, "error", "Admin user not found")
		return c.Redirect(http.StatusSeeOther, "/admin/admins")
	}
	if !targetAdmin.Enabled {
		h.setFlash(c, "success", "Admin user is already disabled")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	if store.NormalizeAdminRole(targetAdmin.Role) == store.AdminRoleOwner {
		ownerCount, countErr := h.store.CountEnabledAdminUsersByRole(store.AdminRoleOwner)
		if countErr != nil {
			h.setFlash(c, "error", "Failed to validate enabled owners")
			return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
		}
		if ownerCount <= 1 {
			h.setFlash(c, "error", "Cannot disable the last enabled owner")
			return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
		}
	}

	if err := h.store.SetAdminUserEnabled(targetAdminID, false); err != nil {
		h.auditAdminAction(c, "admin.user.disable.failure", false, "admin_user", targetAdminID, err, nil)
		h.setFlash(c, "error", "Failed to disable admin user")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	removedSessions, err := h.auth.InvalidateSessionsForAdminUser(c.Request().Context(), targetAdminID)
	if err != nil {
		h.auditAdminAction(c, "admin.user.disable.failure", false, "admin_user", targetAdminID, err, map[string]any{"phase": "session_invalidation"})
		h.setFlash(c, "error", "Admin disabled but failed to invalidate sessions")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	h.auditAdminAction(c, "admin.user.disable.success", true, "admin_user", targetAdminID, nil, map[string]any{
		"invalidated_sessions": removedSessions,
	})
	h.setFlash(c, "success", "Admin user disabled")
	return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
}

func (h *Handler) AdminEnable(c echo.Context) error {
	_, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	targetAdminID := strings.TrimSpace(c.Param("id"))
	if targetAdminID == "" {
		h.setFlash(c, "error", "Invalid admin user ID")
		return c.Redirect(http.StatusSeeOther, "/admin/admins")
	}

	targetAdmin, err := h.store.GetAdminUser(targetAdminID)
	if err != nil {
		h.auditAdminAction(c, "admin.user.enable.failure", false, "admin_user", targetAdminID, err, nil)
		h.setFlash(c, "error", "Admin user not found")
		return c.Redirect(http.StatusSeeOther, "/admin/admins")
	}
	if targetAdmin.Enabled {
		h.setFlash(c, "success", "Admin user is already enabled")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	if err := h.store.SetAdminUserEnabled(targetAdminID, true); err != nil {
		h.auditAdminAction(c, "admin.user.enable.failure", false, "admin_user", targetAdminID, err, nil)
		h.setFlash(c, "error", "Failed to enable admin user")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	h.auditAdminAction(c, "admin.user.enable.success", true, "admin_user", targetAdminID, nil, nil)
	h.setFlash(c, "success", "Admin user enabled")
	return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
}

func (h *Handler) AdminRoleUpdate(c echo.Context) error {
	currentAdmin, err := h.requireOwner(c)
	if err != nil {
		return err
	}
	targetAdminID := strings.TrimSpace(c.Param("id"))
	if targetAdminID == "" {
		h.setFlash(c, "error", "Invalid admin user ID")
		return c.Redirect(http.StatusSeeOther, "/admin/admins")
	}

	targetAdmin, err := h.store.GetAdminUser(targetAdminID)
	if err != nil {
		h.auditAdminAction(c, "admin.user.role_change.failure", false, "admin_user", targetAdminID, err, nil)
		h.setFlash(c, "error", "Admin user not found")
		return c.Redirect(http.StatusSeeOther, "/admin/admins")
	}

	currentRole := store.NormalizeAdminRole(targetAdmin.Role)
	nextRoleRaw := strings.TrimSpace(c.FormValue("role"))
	if !store.IsValidAdminRole(nextRoleRaw) {
		h.setFlash(c, "error", "Invalid admin role")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}
	nextRole := store.NormalizeAdminRole(nextRoleRaw)

	if currentRole == nextRole {
		h.setFlash(c, "success", "Role is already set")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	if currentRole == store.AdminRoleOwner && targetAdmin.Enabled && nextRole != store.AdminRoleOwner {
		ownerCount, countErr := h.store.CountEnabledAdminUsersByRole(store.AdminRoleOwner)
		if countErr != nil {
			h.setFlash(c, "error", "Failed to validate enabled owners")
			return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
		}
		if ownerCount <= 1 {
			h.setFlash(c, "error", "Cannot demote the last enabled owner")
			return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
		}
	}

	if err := h.store.SetAdminUserRole(targetAdminID, nextRole); err != nil {
		h.auditAdminAction(c, "admin.user.role_change.failure", false, "admin_user", targetAdminID, err, map[string]any{
			"old_role":   currentRole,
			"new_role":   nextRole,
			"actor_role": store.NormalizeAdminRole(currentAdmin.Role),
		})
		h.setFlash(c, "error", "Failed to update admin role")
		return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
	}

	h.auditAdminAction(c, "admin.user.role_change.success", true, "admin_user", targetAdminID, nil, map[string]any{
		"old_role":   currentRole,
		"new_role":   nextRole,
		"actor_role": store.NormalizeAdminRole(currentAdmin.Role),
	})
	h.setFlash(c, "success", "Admin role updated")
	return c.Redirect(http.StatusSeeOther, "/admin/admins/"+targetAdminID)
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

	summary := dashboardSummary{
		ClientsTotal: len(clients),
	}
	for _, client := range clients {
		if client.Enabled {
			summary.ClientsEnabled++
		} else {
			summary.ClientsDisabled++
		}
		if client.Confidential {
			summary.ClientsConfidential++
		} else {
			summary.ClientsPublic++
		}
	}

	admins, err := h.store.ListAdminUsers()
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to load admin users")
	}
	summary.AdminsTotal = len(admins)
	for _, item := range admins {
		if item.Enabled {
			summary.AdminsEnabled++
		}
		if store.NormalizeAdminRole(item.Role) == store.AdminRoleOwner {
			summary.OwnersCount++
		} else {
			summary.AdminsRoleCount++
		}
	}

	summary.ActiveInvites, err = h.store.CountActiveAdminInvites(c.Request().Context())
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to count active invites")
	}
	summary.ExpiredUnusedInvites, err = h.store.CountExpiredUnusedAdminInvites(c.Request().Context())
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to count expired invites")
	}

	zeroOffset := 0
	recentEntries, err := h.auditStore.ListAdminAuditEntries(c.Request().Context(), store.AdminAuditListOptions{
		Limit:  dashboardRecentAudit,
		Offset: zeroOffset,
	})
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to load recent audit entries")
	}
	recentAudit := buildDashboardAuditPreview(recentEntries, "")

	failOnly := false
	recentFailuresEntries, err := h.auditStore.ListAdminAuditEntries(c.Request().Context(), store.AdminAuditListOptions{
		Limit:   dashboardRecentFailed,
		Offset:  zeroOffset,
		Success: &failOnly,
	})
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to load recent failures")
	}
	recentFailures := buildDashboardAuditPreview(recentFailuresEntries, "failure")

	clientChangeEntries, err := h.auditStore.ListAdminAuditEntries(c.Request().Context(), store.AdminAuditListOptions{
		Limit:  dashboardRecentClient,
		Offset: zeroOffset,
		Action: "admin.oidc_client",
	})
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to load recent client changes")
	}
	recentClientChanges := buildDashboardAuditPreview(clientChangeEntries, "")

	summary.RecentFailures24hCount, err = h.auditStore.CountAdminAuditFailuresSince(c.Request().Context(), time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		return h.renderInternalError(c, adminUser, "failed to load failure summary")
	}

	pendingInvites := []dashboardPendingInviteItem{}
	now := time.Now().UTC()
	if isAdminOwner(adminUser) {
		pendingRaw, pendingErr := h.store.ListActiveAdminInvites(c.Request().Context(), dashboardPendingLimit)
		if pendingErr != nil {
			return h.renderInternalError(c, adminUser, "failed to load pending invites")
		}
		pendingInvites = make([]dashboardPendingInviteItem, 0, len(pendingRaw))
		for _, item := range pendingRaw {
			expiresAt := item.ExpiresAt.UTC()
			pendingInvites = append(pendingInvites, dashboardPendingInviteItem{
				ID:             item.ID,
				AdminUserID:    strings.TrimSpace(item.AdminUserID),
				AdminLogin:     strings.TrimSpace(item.AdminLogin),
				CreatedBy:      strings.TrimSpace(item.CreatedByLogin),
				CreatedAt:      item.CreatedAt,
				ExpiresAt:      expiresAt,
				ExpiringSoon:   now.Add(24 * time.Hour).After(expiresAt),
				Note:           strings.TrimSpace(item.Note),
				AdminDetailURL: "/admin/admins/" + strings.TrimSpace(item.AdminUserID),
			})
		}
	}

	return h.render(c, http.StatusOK, "index.html", dashboardPageData{
		layoutData:          h.newLayoutData(c, adminUser, "Admin Dashboard"),
		Summary:             summary,
		RecentAudit:         recentAudit,
		RecentFailures:      recentFailures,
		RecentClientChanges: recentClientChanges,
		PendingInvites:      pendingInvites,
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

	if form.Confidential {
		if err := h.requireRecentReauth(c); err != nil {
			return err
		}
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
	if form.Confidential {
		details["recent_reauth"] = true
	}
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
		layoutData:      h.newLayoutData(c, adminUser, "Edit OIDC Client"),
		ClientID:        client.ID,
		Confidential:    client.Confidential,
		OriginalEnabled: client.Enabled,
		Form:            form,
		CreatedAt:       client.CreatedAt,
		UpdatedAt:       client.UpdatedAt,
		RedirectCount:   len(client.RedirectURIs),
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
	if current.Enabled && !form.Enabled {
		if err := h.requireRecentReauth(c); err != nil {
			return err
		}
	}

	validationError := validateClientEditForm(form)
	if validationError != "" {
		opErr = errors.New(validationError)
		details["error"] = "validation_failed"
		return h.render(c, http.StatusBadRequest, "client_edit.html", clientEditPageData{
			layoutData:      h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			ClientID:        clientID,
			Confidential:    current.Confidential,
			OriginalEnabled: current.Enabled,
			Form:            form,
			CreatedAt:       current.CreatedAt,
			UpdatedAt:       current.UpdatedAt,
			RedirectCount:   len(current.RedirectURIs),
			Error:           validationError,
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
	if current.Enabled && !form.Enabled {
		details["recent_reauth"] = true
	}

	if err := h.store.UpdateOIDCClient(updated); err != nil {
		opErr = err
		details["error"] = auditErrorCode(err)
		status, message := mapStoreError(err)
		return h.render(c, status, "client_edit.html", clientEditPageData{
			layoutData:      h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			ClientID:        clientID,
			Confidential:    current.Confidential,
			OriginalEnabled: current.Enabled,
			Form:            form,
			CreatedAt:       current.CreatedAt,
			UpdatedAt:       current.UpdatedAt,
			RedirectCount:   len(current.RedirectURIs),
			Error:           message,
		})
	}

	if err := h.reloadRuntime(c.Request().Context()); err != nil {
		opErr = err
		details["error"] = "runtime_reload_failed"
		return h.render(c, http.StatusInternalServerError, "client_edit.html", clientEditPageData{
			layoutData:      h.newLayoutData(c, adminUser, "Edit OIDC Client"),
			ClientID:        clientID,
			Confidential:    current.Confidential,
			OriginalEnabled: current.Enabled,
			Form:            form,
			CreatedAt:       current.CreatedAt,
			UpdatedAt:       current.UpdatedAt,
			RedirectCount:   len(current.RedirectURIs),
			Error:           "Client updated in storage but runtime reload failed",
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

	if err := h.requireRecentReauth(c); err != nil {
		return err
	}
	details["recent_reauth"] = true

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
	if err := h.requireRecentReauth(c); err != nil {
		return err
	}
	details["recent_reauth"] = true

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
		fromCtx.Role = store.NormalizeAdminRole(fromCtx.Role)
		return fromCtx
	}
	adminUser, _ := h.auth.SessionUser(c)
	if adminUser != nil {
		adminUser.Role = store.NormalizeAdminRole(adminUser.Role)
	}
	return adminUser
}

func isAdminOwner(adminUser *store.AdminUser) bool {
	if adminUser == nil {
		return false
	}
	return store.NormalizeAdminRole(adminUser.Role) == store.AdminRoleOwner
}

func (h *Handler) requireOwner(c echo.Context) (*store.AdminUser, error) {
	adminUser := h.currentAdmin(c)
	if adminUser == nil {
		return nil, c.String(http.StatusUnauthorized, "admin session is required")
	}
	if isAdminOwner(adminUser) {
		return adminUser, nil
	}
	h.auditAdminAction(c, "admin.guard.permission_denied", false, "", "", nil, map[string]any{
		"required_role": "owner",
		"actor_role":    store.NormalizeAdminRole(adminUser.Role),
		"path":          strings.TrimSpace(c.Path()),
		"method":        strings.TrimSpace(c.Request().Method),
	})
	return nil, c.String(http.StatusForbidden, "owner role required")
}

func (h *Handler) recentReauthMaxAge() time.Duration {
	maxAge := h.auth.ReauthMaxAge()
	if maxAge <= 0 {
		return 5 * time.Minute
	}
	return maxAge
}

func (h *Handler) requireRecentReauth(c echo.Context) error {
	maxAge := h.recentReauthMaxAge()
	if h.auth.HasRecentReauth(c, maxAge) {
		return nil
	}
	if err := h.reauthRequiredResponse(c); err != nil {
		return err
	}
	return echo.ErrForbidden
}

func (h *Handler) reauthRequiredResponse(c echo.Context) error {
	payload := map[string]string{
		"message": "recent admin re-auth required",
		"code":    "admin_reauth_required",
	}
	if requestWantsJSON(c) {
		return c.JSON(http.StatusForbidden, payload)
	}
	return c.String(http.StatusForbidden, payload["message"])
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
		Title:            strings.TrimSpace(title),
		Admin:            adminUser,
		IsOwner:          isAdminOwner(adminUser),
		Flash:            h.popFlash(c),
		CSRFToken:        csrfToken,
		ReauthTTLSeconds: int(h.recentReauthMaxAge().Seconds()),
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

func parseListPage(raw string) int {
	return parseAuditLogPage(raw)
}

func parseUserEventsFilter(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auth":
		return "auth"
	case "recovery":
		return "recovery"
	case "passkeys":
		return "passkeys"
	case "sessions":
		return "sessions"
	case "admin":
		return "admin"
	default:
		return "all"
	}
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

func usersListURL(page int, query string) string {
	params := url.Values{}
	if page > 1 {
		params.Set("page", strconv.Itoa(page))
	}
	if strings.TrimSpace(query) != "" {
		params.Set("q", strings.TrimSpace(query))
	}
	encoded := params.Encode()
	if encoded == "" {
		return "/admin/users"
	}
	return "/admin/users?" + encoded
}

func userDetailEventsURL(userID string, category string) string {
	base := "/admin/users/" + url.PathEscape(strings.TrimSpace(userID))
	category = parseUserEventsFilter(category)
	if category == "all" {
		return base
	}
	params := url.Values{}
	params.Set("events", category)
	return base + "?" + params.Encode()
}

func buildUserTimelineFilterLinks(userID string, selected string) []userTimelineFilterLink {
	selected = parseUserEventsFilter(selected)
	options := []struct {
		Value string
		Label string
	}{
		{Value: "all", Label: "All"},
		{Value: "auth", Label: "Auth"},
		{Value: "recovery", Label: "Recovery"},
		{Value: "passkeys", Label: "Passkeys"},
		{Value: "sessions", Label: "Sessions"},
		{Value: "admin", Label: "Admin actions"},
	}

	out := make([]userTimelineFilterLink, 0, len(options))
	for _, option := range options {
		value := parseUserEventsFilter(option.Value)
		out = append(out, userTimelineFilterLink{
			Value:  value,
			Label:  option.Label,
			URL:    userDetailEventsURL(userID, value),
			Active: selected == value,
		})
	}
	return out
}

func buildDashboardAuditPreview(entries []store.AdminAuditEntry, successFilter string) []dashboardAuditPreviewItem {
	out := make([]dashboardAuditPreviewItem, 0, len(entries))
	for _, entry := range entries {
		action := strings.TrimSpace(entry.Action)
		actorID := strings.TrimSpace(entry.ActorID)
		resourceID := strings.TrimSpace(entry.ResourceID)
		resourceType := strings.TrimSpace(entry.ResourceType)
		out = append(out, dashboardAuditPreviewItem{
			CreatedAt:    entry.CreatedAt,
			Action:       action,
			Success:      entry.Success,
			Actor:        formatAuditActor(entry.ActorType, actorID),
			ResourceType: defaultDisplay(resourceType),
			ResourceID:   defaultDisplay(resourceID),
			RequestID:    defaultDisplay(strings.TrimSpace(entry.RequestID)),
			AuditURL:     auditLogURL(1, action, successFilter, actorID, resourceID),
		})
	}
	return out
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

func buildPasskeyViews(items []store.AdminCredentialInfo) []adminPasskeyView {
	out := make([]adminPasskeyView, 0, len(items))
	for _, item := range items {
		credentialID := strings.TrimSpace(item.CredentialID)
		out = append(out, adminPasskeyView{
			ID:            item.ID,
			CredentialID:  credentialID,
			CredentialTag: shortDisplay(credentialID, 12, 10),
			CreatedAt:     item.CreatedAt,
			LastUsedAt:    item.LastUsedAt,
			Transports:    append([]string(nil), item.Transports...),
		})
	}
	return out
}

func buildSessionViews(items []store.AdminSessionInfo) []adminSessionView {
	out := make([]adminSessionView, 0, len(items))
	for _, item := range items {
		sessionID := strings.TrimSpace(item.SessionID)
		out = append(out, adminSessionView{
			SessionID:  sessionID,
			SessionTag: shortDisplay(sessionID, 10, 8),
			CreatedAt:  item.CreatedAt,
			LastSeenAt: item.LastSeenAt,
			ExpiresAt:  item.ExpiresAt,
			RemoteIP:   defaultDisplay(item.RemoteIP),
			UserAgent:  defaultDisplay(item.UserAgent),
			Current:    item.Current,
		})
	}
	return out
}

func buildUserPasskeyViews(items []store.CredentialRecord) []userPasskeyView {
	out := make([]userPasskeyView, 0, len(items))
	for _, item := range items {
		credentialID := hex.EncodeToString(item.ID)
		label := strings.TrimSpace(item.DeviceName)
		if label == "" {
			label = shortDisplay(credentialID, 12, 8)
		}
		out = append(out, userPasskeyView{
			CredentialID: credentialID,
			Label:        label,
			CreatedAt:    item.CreatedAt,
			LastUsedAt:   item.LastUsedAt,
		})
	}
	return out
}

func buildUserSessionViews(items []store.UserSessionInfo) []userSessionView {
	out := make([]userSessionView, 0, len(items))
	for _, item := range items {
		sessionID := strings.TrimSpace(item.SessionID)
		out = append(out, userSessionView{
			SessionID:  sessionID,
			SessionTag: shortDisplay(sessionID, 10, 8),
			CreatedAt:  item.CreatedAt,
			LastSeenAt: item.LastSeenAt,
			ExpiresAt:  item.ExpiresAt,
			RemoteIP:   defaultDisplay(item.RemoteIP),
			UserAgent:  defaultDisplay(item.UserAgent),
		})
	}
	return out
}

func buildUserClientViews(items []store.UserOIDCClient) []userClientView {
	out := make([]userClientView, 0, len(items))
	for _, item := range items {
		out = append(out, userClientView{
			ClientID:    strings.TrimSpace(item.ClientID),
			ClientHost:  strings.TrimSpace(item.ClientHost),
			FirstSeenAt: item.FirstSeenAt,
			LastSeenAt:  item.LastSeenAt,
		})
	}
	return out
}

func shortDisplay(value string, head int, tail int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	if head < 1 || tail < 1 {
		return value
	}
	if len(value) <= head+tail+1 {
		return value
	}
	return value[:head] + "..." + value[len(value)-tail:]
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

func requestWantsJSON(c echo.Context) bool {
	accept := strings.ToLower(strings.TrimSpace(c.Request().Header.Get(echo.HeaderAccept)))
	if strings.Contains(accept, "application/json") {
		return true
	}
	if strings.TrimSpace(c.Request().Header.Get("X-Requested-With")) == "XMLHttpRequest" {
		return true
	}
	if strings.TrimSpace(c.Request().Header.Get("X-Admin-Reauth-Flow")) == "1" {
		return true
	}
	contentType := strings.ToLower(strings.TrimSpace(c.Request().Header.Get(echo.HeaderContentType)))
	return strings.Contains(contentType, "application/json")
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

func (h *Handler) auditAdminAction(c echo.Context, action string, success bool, resourceType string, resourceID string, opErr error, details map[string]any) {
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
		log.Printf("admin ui action=%s actor_type=%s actor_id=%s resource_type=%s resource_id=%s ip=%s request_id=%s success=true", action, actorType, actorID, strings.TrimSpace(resourceType), strings.TrimSpace(resourceID), realIP, reqID)
	} else {
		log.Printf("admin ui action=%s actor_type=%s actor_id=%s resource_type=%s resource_id=%s ip=%s request_id=%s success=false error=operation_failed", action, actorType, actorID, strings.TrimSpace(resourceType), strings.TrimSpace(resourceID), realIP, reqID)
	}

	if h.auditStore == nil {
		return
	}
	payload := map[string]any{}
	for key, value := range details {
		trimmed := strings.ToLower(strings.TrimSpace(key))
		if trimmed == "" {
			continue
		}
		payload[trimmed] = sanitizeAuditDetails(value)
	}
	if opErr != nil && payload["error"] == nil {
		payload["error"] = "operation_failed"
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		encoded = json.RawMessage(`{}`)
	}
	entry := store.AdminAuditEntry{
		Action:       strings.TrimSpace(action),
		Success:      success,
		ActorType:    actorType,
		ActorID:      actorID,
		RemoteIP:     realIP,
		RequestID:    reqID,
		ResourceType: strings.TrimSpace(resourceType),
		ResourceID:   strings.TrimSpace(resourceID),
		DetailsJSON:  encoded,
	}
	if err := h.auditStore.CreateAdminAuditEntry(c.Request().Context(), entry); err != nil {
		log.Printf("admin ui audit insert failed action=%s resource_type=%s resource_id=%s request_id=%s error=%v", action, resourceType, resourceID, reqID, err)
	}
}

func parseInviteTTLHours(raw string, fallback int) int {
	value := strings.TrimSpace(raw)
	if value == "" {
		if fallback > 0 {
			return fallback
		}
		return defaultInviteTTLHours
	}
	hours, err := strconv.Atoi(value)
	if err != nil || hours <= 0 {
		return fallback
	}
	if hours > 24*30 {
		return 24 * 30
	}
	return hours
}

func newInviteToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashInviteToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func buildInviteURL(c echo.Context, token string) string {
	scheme := strings.TrimSpace(c.Scheme())
	if scheme == "" {
		scheme = "https"
	}
	host := strings.TrimSpace(c.Request().Host)
	if host == "" {
		host = "admin.ahoj420.eu"
	}
	return scheme + "://" + host + "/admin/invite/" + url.PathEscape(strings.TrimSpace(token))
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
