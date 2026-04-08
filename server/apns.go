package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// apnsTokenRegex 校验 APNs device token 格式：64 位以上的十六进制字符串
var apnsTokenRegex = regexp.MustCompile(`^[0-9a-fA-F]{64,}$`)

// pushEventMeta 定义推送事件的元数据
type pushEventMeta struct {
	Title    string
	Category string
}

// pushEventMap 映射事件类型到推送元数据
var pushEventMap = map[string]pushEventMeta{
	"approval_required": {Title: "权限审批", Category: "APPROVAL_REQUEST"},
	"task_complete":     {Title: "任务完成", Category: "TASK_COMPLETE"},
	"task_failed":       {Title: "任务失败", Category: "TASK_FAILED"},
	"terminal_exit":     {Title: "终端退出", Category: "TERMINAL_EXIT"},
	"notification":      {Title: "终端通知", Category: "TERMINAL_NOTIFICATION"},
}

// shouldPush 判断事件类型是否需要推送通知
func shouldPush(eventType string) bool {
	_, ok := pushEventMap[eventType]
	return ok
}

// APNsClient 封装 APNs HTTP/2 推送客户端
type APNsClient struct {
	httpClient *http.Client
	teamID     string
	keyID      string
	bundleID   string
	privateKey *ecdsa.PrivateKey

	// JWT 缓存（有效期 50 分钟，APNs 允许 60 分钟）
	mu             sync.Mutex
	cachedToken    string
	tokenExpiresAt time.Time
}

// NewAPNsClient 创建 APNsClient 实例
// keyPath 为 p8 私钥文件路径；如果任何参数为空，SendPush 静默返回 nil
func NewAPNsClient(teamID, keyID, bundleID, keyPath string) *APNsClient {
	c := &APNsClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		teamID:     teamID,
		keyID:      keyID,
		bundleID:   bundleID,
	}

	if keyPath != "" {
		key, err := loadP8Key(keyPath)
		if err != nil {
			log.Printf("[apns] 加载 p8 私钥失败: %v", err)
		} else {
			c.privateKey = key
			log.Printf("[apns] p8 私钥加载成功 teamID=%s keyID=%s bundleID=%s", teamID, keyID, bundleID)
		}
	}

	return c
}

// loadP8Key 从 .p8 文件加载 ECDSA P-256 私钥
func loadP8Key(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("无法解码 PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("私钥不是 ECDSA 类型")
	}

	return ecKey, nil
}

// generateJWT 生成 APNs JWT token（ES256 签名）
func (c *APNsClient) generateJWT() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 缓存有效则直接返回
	if c.cachedToken != "" && time.Now().Before(c.tokenExpiresAt) {
		return c.cachedToken, nil
	}

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": c.teamID,
		"iat": now.Unix(),
	})
	token.Header["kid"] = c.keyID

	signed, err := token.SignedString(c.privateKey)
	if err != nil {
		return "", fmt.Errorf("JWT 签名失败: %w", err)
	}

	// 缓存 50 分钟（APNs 允许 60 分钟）
	c.cachedToken = signed
	c.tokenExpiresAt = now.Add(50 * time.Minute)

	return signed, nil
}

// SendPush 向设备推送通知
func (c *APNsClient) SendPush(deviceToken, eventType, summary string) error {
	if c == nil || c.bundleID == "" || c.privateKey == nil {
		return nil
	}

	// 校验 deviceToken 格式，防止 URL 注入
	if !apnsTokenRegex.MatchString(deviceToken) {
		return fmt.Errorf("apns: invalid device token format")
	}

	payload := buildAPNsPayload(eventType, summary)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("apns: marshal payload: %w", err)
	}

	jwtToken, err := c.generateJWT()
	if err != nil {
		return fmt.Errorf("apns: generate jwt: %w", err)
	}

	url := fmt.Sprintf("https://api.push.apple.com/3/device/%s", deviceToken)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("apns: create request: %w", err)
	}

	req.Header.Set("apns-topic", c.bundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("authorization", "bearer "+jwtToken)
	req.Header.Set("content-type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("apns: http request: %w", err)
	}
	defer resp.Body.Close()

	tokenPreview := deviceToken
	if len(tokenPreview) > 16 {
		tokenPreview = tokenPreview[:16]
	}

	if resp.StatusCode != http.StatusOK {
		// 读取并解析 APNs 错误响应体，提取 reason 字段
		var reason string
		if body, err := io.ReadAll(io.LimitReader(resp.Body, 1024)); err == nil && len(body) > 0 {
			var apnsErr struct {
				Reason string `json:"reason"`
			}
			if json.Unmarshal(body, &apnsErr) == nil && apnsErr.Reason != "" {
				reason = apnsErr.Reason
			}
		}
		if reason != "" {
			log.Printf("[apns] push failed device=%s status=%d reason=%s", tokenPreview, resp.StatusCode, reason)
			return fmt.Errorf("apns: unexpected status %d reason=%s", resp.StatusCode, reason)
		}
		log.Printf("[apns] push failed device=%s status=%d", tokenPreview, resp.StatusCode)
		return fmt.Errorf("apns: unexpected status %d", resp.StatusCode)
	}

	log.Printf("[apns] push sent device=%s event=%s", tokenPreview, eventType)
	return nil
}

// buildAPNsPayload 根据事件类型和摘要构建 APNs JSON payload
func buildAPNsPayload(eventType, summary string) map[string]interface{} {
	meta, ok := pushEventMap[eventType]
	if !ok {
		meta = pushEventMeta{Title: "cmux 通知", Category: "GENERAL"}
	}

	return map[string]interface{}{
		"aps": map[string]interface{}{
			"alert": map[string]interface{}{
				"title": meta.Title,
				"body":  summary,
			},
			"sound":    "default",
			"category": meta.Category,
		},
		"event_type": eventType,
	}
}
