package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const gosmsHTTPTimeout = 15 * time.Second

type smsSender interface {
	SendSMS(ctx context.Context, to, message string) error
}

type goSMSSender struct {
	baseURL      string
	clientID     string
	clientSecret string
	channelID    int
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

type goSMSTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type goSMSSendMessageRequest struct {
	Message    string      `json:"message"`
	Recipients interface{} `json:"recipients"`
	Channel    int         `json:"channel"`
}

func newSMSSenderFromEnv() (smsSender, error) {
	clientID := strings.TrimSpace(os.Getenv("GOSMS_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("GOSMS_CLIENT_SECRET"))
	channelRaw := strings.TrimSpace(os.Getenv("GOSMS_CHANNEL_ID"))
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("GOSMS_BASE_URL")), "/")
	if baseURL == "" {
		baseURL = "https://app.gosms.eu"
	}

	if clientID == "" && clientSecret == "" && channelRaw == "" {
		return nil, nil
	}
	if clientID == "" || clientSecret == "" || channelRaw == "" {
		return nil, fmt.Errorf("GoSMS config incomplete: GOSMS_CLIENT_ID, GOSMS_CLIENT_SECRET, GOSMS_CHANNEL_ID are required")
	}

	channelID, err := strconv.Atoi(channelRaw)
	if err != nil || channelID <= 0 {
		return nil, fmt.Errorf("GoSMS config invalid: bad GOSMS_CHANNEL_ID %q", channelRaw)
	}

	return &goSMSSender{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		channelID:    channelID,
		httpClient:   &http.Client{Timeout: gosmsHTTPTimeout},
	}, nil
}

func (s *goSMSSender) SendSMS(ctx context.Context, to, message string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("phone recipient is empty")
	}
	if strings.TrimSpace(message) == "" {
		return fmt.Errorf("sms message is empty")
	}

	token, err := s.getAccessToken(ctx)
	if err != nil {
		return err
	}

	body, err := json.Marshal(goSMSSendMessageRequest{
		Message:    message,
		Recipients: to,
		Channel:    s.channelID,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/api/v1/messages", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gosms send failed: status %d", resp.StatusCode)
	}
	return nil
}

func (s *goSMSSender) getAccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.accessToken != "" && time.Now().Before(s.expiresAt.Add(-30*time.Second)) {
		token := s.accessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	values := url.Values{}
	values.Set("client_id", s.clientID)
	values.Set("client_secret", s.clientSecret)
	values.Set("grant_type", "client_credentials")

	tokenURL := s.baseURL + "/oauth/v2/token?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gosms token failed: status %d", resp.StatusCode)
	}

	var tokenResp goSMSTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", fmt.Errorf("gosms token response missing access_token")
	}
	if tokenResp.ExpiresIn <= 0 {
		tokenResp.ExpiresIn = 3600
	}

	s.mu.Lock()
	s.accessToken = tokenResp.AccessToken
	s.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	s.mu.Unlock()

	return tokenResp.AccessToken, nil
}
