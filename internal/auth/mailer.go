package auth

import (
	"fmt"
	"mime"
	"net/smtp"
	"os"
	"strconv"
	"strings"
)

type emailSender interface {
	Send(to, subject, textBody string) error
}

type smtpEmailSender struct {
	host     string
	port     int
	username string
	password string
	from     string
	fromName string
}

func newEmailSenderFromEnv() (emailSender, error) {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	portRaw := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	username := strings.TrimSpace(os.Getenv("SMTP_USERNAME"))
	password := strings.TrimSpace(os.Getenv("SMTP_PASSWORD"))
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	fromName := strings.TrimSpace(os.Getenv("SMTP_FROM_NAME"))

	// Not configured: keep legacy log-only behavior.
	if host == "" && portRaw == "" && username == "" && password == "" && from == "" && fromName == "" {
		return nil, nil
	}
	if host == "" || portRaw == "" || from == "" {
		return nil, fmt.Errorf("SMTP config incomplete: SMTP_HOST, SMTP_PORT and SMTP_FROM are required")
	}
	if (username == "") != (password == "") {
		return nil, fmt.Errorf("SMTP config invalid: SMTP_USERNAME and SMTP_PASSWORD must be set together")
	}

	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 {
		return nil, fmt.Errorf("SMTP config invalid: bad SMTP_PORT %q", portRaw)
	}

	return &smtpEmailSender{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
		fromName: fromName,
	}, nil
}

func (s *smtpEmailSender) Send(to, subject, textBody string) error {
	if s == nil {
		return fmt.Errorf("smtp sender is nil")
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("email recipient is empty")
	}

	fromHeader := s.from
	if s.fromName != "" {
		fromHeader = mime.QEncoding.Encode("utf-8", s.fromName) + " <" + s.from + ">"
	}

	msg := strings.Join([]string{
		"From: " + fromHeader,
		"To: " + to,
		"Subject: " + mime.QEncoding.Encode("utf-8", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		textBody,
		"",
	}, "\r\n")

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}
	return smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
}
