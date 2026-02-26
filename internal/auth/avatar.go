package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/draw"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"strings"

	"github.com/chai2010/webp"
	"github.com/labstack/echo/v4"
	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/webp"

	"github.com/houbamydar/AHOJ420/internal/avatar"
)

const (
	avatarMaxInputDimension = 4096
	avatarMaxInputPixels    = int64(4096 * 4096)
)

func (s *Service) UploadAvatar(c echo.Context) error {
	if mode, _ := s.isRecoveryMode(c); mode {
		return c.JSON(http.StatusForbidden, map[string]any{"message": "recovery setup required", "redirect": "/?mode=recovery"})
	}

	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}
	if strings.TrimSpace(s.avatarCfg.zone) == "" || strings.TrimSpace(s.avatarCfg.accessKey) == "" {
		return c.String(http.StatusInternalServerError, "Avatar storage is not configured")
	}

	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, s.avatarCfg.maxBytes+1024)
	if err := c.Request().ParseMultipartForm(s.avatarCfg.maxBytes + 1024); err != nil {
		return c.String(http.StatusBadRequest, "Invalid multipart payload")
	}

	file, hdr, err := c.Request().FormFile("file")
	if err != nil {
		return c.String(http.StatusBadRequest, "file is required")
	}
	defer file.Close()

	raw, err := readLimited(file, s.avatarCfg.maxBytes)
	if err != nil {
		if errors.Is(err, errTooLarge) {
			return c.String(http.StatusBadRequest, "File too large")
		}
		return c.String(http.StatusBadRequest, "Failed to read file")
	}
	if !isAllowedImage(hdr) {
		return c.String(http.StatusBadRequest, "Only jpg/png/webp are allowed")
	}

	webpBytes, err := normalizeToWebP(raw, 256)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid image")
	}

	avatarKey := path.Join("avatars", userID+".webp")
	if err := s.putBunnyObject(c.Request().Context(), avatarKey, webpBytes, "image/webp"); err != nil {
		return c.String(http.StatusBadGateway, "Failed to upload avatar")
	}
	if err := s.store.UpdateAvatar(userID, avatarKey, "image/webp", int64(len(webpBytes))); err != nil {
		return c.String(http.StatusInternalServerError, "Failed to update avatar metadata")
	}

	user, err := s.store.GetUser(userID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to load user")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"picture_url": avatar.BuildPublicURL(s.avatarCfg.publicBase, user.AvatarKey, user.AvatarUpdatedAt),
	})
}

func (s *Service) putBunnyObject(ctx context.Context, avatarKey string, data []byte, contentType string) error {
	endpoint := strings.TrimSuffix(strings.TrimSpace(s.avatarCfg.endpoint), "/")
	zone := strings.Trim(strings.TrimSpace(s.avatarCfg.zone), "/")
	if endpoint == "" || zone == "" {
		return fmt.Errorf("bunny endpoint/zone is empty")
	}

	url := fmt.Sprintf("https://%s/%s/%s", endpoint, zone, strings.TrimPrefix(avatarKey, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("AccessKey", s.avatarCfg.accessKey)
	req.Header.Set("Content-Type", contentType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("bunny upload failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	return nil
}

var errTooLarge = errors.New("file too large")
var errImageTooLargeDimensions = errors.New("image dimensions too large")
var errImageTooManyPixels = errors.New("image has too many pixels")
var errInvalidOutputSize = errors.New("invalid output size")

func readLimited(file multipart.File, maxBytes int64) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxBytes {
		return nil, errTooLarge
	}
	return buf, nil
}

func isAllowedImage(hdr *multipart.FileHeader) bool {
	ct := strings.ToLower(strings.TrimSpace(hdr.Header.Get("Content-Type")))
	switch ct {
	case "image/jpeg", "image/jpg", "image/png", "image/webp":
		return true
	default:
		return false
	}
}

func normalizeToWebP(raw []byte, size int) ([]byte, error) {
	if size <= 0 {
		return nil, errInvalidOutputSize
	}

	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, errImageTooLargeDimensions
	}
	if cfg.Width > avatarMaxInputDimension || cfg.Height > avatarMaxInputDimension {
		return nil, errImageTooLargeDimensions
	}
	if int64(cfg.Width)*int64(cfg.Height) > avatarMaxInputPixels {
		return nil, errImageTooManyPixels
	}

	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}

	bounds := img.Bounds()
	if bounds.Dx() <= 0 || bounds.Dy() <= 0 {
		return nil, errImageTooLargeDimensions
	}
	if bounds.Dx() > avatarMaxInputDimension || bounds.Dy() > avatarMaxInputDimension {
		return nil, errImageTooLargeDimensions
	}
	if int64(bounds.Dx())*int64(bounds.Dy()) > avatarMaxInputPixels {
		return nil, errImageTooManyPixels
	}

	side := bounds.Dx()
	if bounds.Dy() < side {
		side = bounds.Dy()
	}
	offX := bounds.Min.X + (bounds.Dx()-side)/2
	offY := bounds.Min.Y + (bounds.Dy()-side)/2
	srcRect := image.Rect(offX, offY, offX+side, offY+side)

	resized := image.NewRGBA(image.Rect(0, 0, size, size))
	xdraw.ApproxBiLinear.Scale(resized, resized.Bounds(), img, srcRect, draw.Src, nil)

	var out bytes.Buffer
	if err := webp.Encode(&out, resized, &webp.Options{Lossless: false, Quality: 80}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
