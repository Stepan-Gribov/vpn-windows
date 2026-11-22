// SPDX-FileCopyrightText: 2026 KindlyVPN contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package clientcore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	maxOneMEEndpoint      = "wss://ws-api.oneme.ru/websocket"
	maxOrigin             = "https://web.max.ru"
	maxCallsEndpoint      = "https://calls.okcdn.ru/fb.do"
	maxApplicationKey     = "CNHIJPLGDIHBABABA"
	maxCredentialCacheTTL = 30 * time.Second
)

type maxWireMessage struct {
	Sequence int             `json:"seq"`
	Opcode   int             `json:"opcode"`
	Payload  json.RawMessage `json:"payload"`
	Version  int             `json:"ver"`
	Command  int             `json:"cmd"`
}

type maxCredentialSet struct {
	username string
	password string
	address  string
	expires  time.Time
	token    string
	peerID   string
	udp      bool
}

var maxCredentialCache struct {
	sync.Mutex
	value maxCredentialSet
}

func getMAXCredsCached(ctx context.Context, token, peerID string, udp bool, streamID int) (string, string, string, error) {
	maxCredentialCache.Lock()
	defer maxCredentialCache.Unlock()

	now := time.Now()
	cached := maxCredentialCache.value
	if cached.token == token && cached.peerID == peerID && cached.udp == udp && now.Before(cached.expires) {
		debugf("[STREAM %d] Reusing MAX TURN credentials", streamID)
		return cached.username, cached.password, cached.address, nil
	}

	username, password, address, err := getMAXCreds(ctx, token, peerID, udp)
	if err != nil {
		return "", "", "", err
	}
	maxCredentialCache.value = maxCredentialSet{
		username: username,
		password: password,
		address:  address,
		expires:  now.Add(maxCredentialCacheTTL),
		token:    token,
		peerID:   peerID,
		udp:      udp,
	}
	return username, password, address, nil
}

func getMAXCreds(ctx context.Context, token, peerID string, udp bool) (string, string, string, error) {
	token = strings.TrimSpace(token)
	peerID = strings.TrimSpace(peerID)
	if token == "" {
		return "", "", "", fmt.Errorf("MAX auth token is empty")
	}
	if !isDecimalID(peerID) {
		return "", "", "", fmt.Errorf("MAX peer ID must contain digits only")
	}

	callToken, err := getMAXCallToken(ctx, token)
	if err != nil {
		return "", "", "", fmt.Errorf("MAX call token: %w", err)
	}
	sessionKey, err := loginMAXCalls(ctx, callToken)
	if err != nil {
		return "", "", "", fmt.Errorf("MAX calls login: %w", err)
	}
	username, password, address, err := startMAXConversation(ctx, sessionKey, peerID, udp)
	if err != nil {
		return "", "", "", fmt.Errorf("MAX conversation: %w", err)
	}
	return username, password, address, nil
}

func getMAXCallToken(ctx context.Context, authToken string) (string, error) {
	header := http.Header{}
	header.Set("Origin", maxOrigin)
	conn, response, err := websocket.DefaultDialer.DialContext(ctx, maxOneMEEndpoint, header)
	if err != nil {
		if response != nil {
			return "", fmt.Errorf("websocket status %s: %w", response.Status, err)
		}
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return "", err
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return "", err
	}

	deviceID := uuid.NewString()
	hello := map[string]any{
		"userAgent": map[string]any{
			"deviceType":      "WEB",
			"locale":          "ru",
			"deviceLocale":    "ru",
			"osVersion":       "Android",
			"deviceName":      "KindlyVPN",
			"headerUserAgent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/142.0.0.0 Mobile Safari/537.36",
			"appVersion":      "25.11.2",
			"screen":          "1080x1920 1.0x",
			"timezone":        "Europe/Moscow",
		},
		"deviceId": deviceID,
	}
	if _, err := maxWebSocketRequest(conn, 0, 6, hello); err != nil {
		return "", fmt.Errorf("client hello: %w", err)
	}

	syncPayload := map[string]any{
		"token":        authToken,
		"interactive":  false,
		"chatsCount":   0,
		"chatsSync":    0,
		"contactsSync": 0,
		"presenceSync": 0,
		"draftsSync":   0,
	}
	if _, err := maxWebSocketRequest(conn, 1, 19, syncPayload); err != nil {
		return "", fmt.Errorf("chat sync: %w", err)
	}

	payload, err := maxWebSocketRequest(conn, 2, 158, map[string]any{})
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", fmt.Errorf("response contained no token")
	}
	return result.Token, nil
}

func maxWebSocketRequest(conn *websocket.Conn, sequence, opcode int, payload any) (json.RawMessage, error) {
	request := map[string]any{
		"seq":     sequence,
		"opcode":  opcode,
		"payload": payload,
		"ver":     11,
		"cmd":     0,
	}
	if err := conn.WriteJSON(request); err != nil {
		return nil, err
	}

	for {
		var response maxWireMessage
		if err := conn.ReadJSON(&response); err != nil {
			return nil, err
		}
		if response.Sequence != sequence || response.Command != 1 {
			continue
		}
		var errorPayload struct {
			Error any `json:"error"`
		}
		if err := json.Unmarshal(response.Payload, &errorPayload); err == nil && errorPayload.Error != nil {
			return nil, fmt.Errorf("server error: %v", errorPayload.Error)
		}
		return response.Payload, nil
	}
}

func loginMAXCalls(ctx context.Context, callToken string) (string, error) {
	sessionData, err := json.Marshal(map[string]any{
		"auth_token":     callToken,
		"client_type":    "SDK_JS",
		"client_version": "1.1",
		"device_id":      uuid.NewString(),
		"version":        3,
	})
	if err != nil {
		return "", err
	}
	payload, err := postMAXCalls(ctx, url.Values{
		"method":       {"auth.anonymLogin"},
		"session_data": {string(sessionData)},
	})
	if err != nil {
		return "", err
	}
	var result struct {
		SessionKey string `json:"session_key"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return "", err
	}
	if result.SessionKey == "" {
		return "", maxAPIError(payload, "response contained no session_key")
	}
	return result.SessionKey, nil
}

func startMAXConversation(ctx context.Context, sessionKey, peerID string, udp bool) (string, string, string, error) {
	payload, err := postMAXCalls(ctx, url.Values{
		"method":          {"vchat.startConversation"},
		"session_key":     {sessionKey},
		"conversationId":  {uuid.NewString()},
		"isVideo":         {"false"},
		"protocolVersion": {"5"},
		"externalIds":     {peerID},
		"payload":         {`{"is_video":false}`},
	})
	if err != nil {
		return "", "", "", err
	}
	var result struct {
		TURNServer struct {
			URLs       []string `json:"urls"`
			Username   string   `json:"username"`
			Credential string   `json:"credential"`
		} `json:"turn_server"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return "", "", "", err
	}
	if result.TURNServer.Username == "" || result.TURNServer.Credential == "" || len(result.TURNServer.URLs) == 0 {
		return "", "", "", maxAPIError(payload, "response contained no TURN credentials")
	}
	address, err := normalizeMAXTURNURL(result.TURNServer.URLs, udp)
	if err != nil {
		return "", "", "", err
	}
	return result.TURNServer.Username, result.TURNServer.Credential, address, nil
}

func postMAXCalls(ctx context.Context, values url.Values) ([]byte, error) {
	values.Set("format", "JSON")
	values.Set("application_key", maxApplicationKey)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, maxCallsEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, fmt.Errorf("MAX calls response exceeded 1 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %s", response.Status)
	}
	return body, nil
}

func normalizeMAXTURNURL(urls []string, udp bool) (string, error) {
	preferredTransport := "tcp"
	if udp {
		preferredTransport = "udp"
	}
	var fallback string
	for _, raw := range urls {
		candidate := strings.TrimSpace(raw)
		if !strings.HasPrefix(candidate, "turn:") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(candidate, "turn:"), "?", 2)
		candidate = parts[0]
		if host, port, err := net.SplitHostPort(candidate); err == nil && host != "" && port != "" {
			if len(parts) == 2 {
				query, err := url.ParseQuery(parts[1])
				if err != nil {
					continue
				}
				transport := strings.ToLower(query.Get("transport"))
				if transport == preferredTransport {
					return candidate, nil
				}
				if transport != "" {
					continue
				}
			}
			if fallback == "" {
				fallback = candidate
			}
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("MAX response contained no usable TURN URL")
}

func maxAPIError(payload []byte, fallback string) error {
	var response map[string]any
	if err := json.Unmarshal(payload, &response); err == nil {
		for _, key := range []string{"error_msg", "error", "message"} {
			if value, ok := response[key]; ok && fmt.Sprint(value) != "" {
				return fmt.Errorf("%v", value)
			}
		}
	}
	return fmt.Errorf("%s", fallback)
}

func isDecimalID(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
