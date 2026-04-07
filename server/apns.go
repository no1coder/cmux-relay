package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// pushEventMeta 定义推送事件的元数据
type pushEventMeta struct {
	// Title 是推送通知的标题
	Title string
	// Category 是 APNs 的通知分类
	Category string
}

// pushEventMap 映射事件类型到推送元数据
var pushEventMap = map[string]pushEventMeta{
	"approval_required": {Title: "权限审批", Category: "APPROVAL_REQUEST"},
	"task_complete":     {Title: "任务完成", Category: "TASK_COMPLETE"},
	"task_failed":       {Title: "任务失败", Category: "TASK_FAILED"},
	"terminal_exit":     {Title: "终端退出", Category: "TERMINAL_EXIT"},
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
}

// NewAPNsClient 创建 APNsClient 实例
// teamID、keyID、bundleID 为空时，SendPush 会静默返回 nil
func NewAPNsClient(teamID, keyID, bundleID string) *APNsClient {
	return &APNsClient{
		httpClient: &http.Client{},
		teamID:     teamID,
		keyID:      keyID,
		bundleID:   bundleID,
	}
}

// SendPush 向设备推送通知。
// 如果 bundleID、teamID 或 keyID 未配置，则静默返回 nil（功能关闭）。
func (c *APNsClient) SendPush(deviceToken, eventType, summary string) error {
	// 未配置时静默跳过
	if c == nil || c.bundleID == "" {
		return nil
	}
	// teamID 或 keyID 缺失时无法生成有效 JWT，提前返回避免发送无效请求
	if c.teamID == "" || c.keyID == "" {
		return nil
	}

	payload := buildAPNsPayload(eventType, summary)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("apns: marshal payload: %w", err)
	}

	// TODO: 实现 JWT token 签名（需要 p8 私钥）
	// JWT header: {"alg":"ES256","kid":"<keyID>"}
	// JWT claims: {"iss":"<teamID>","iat":<unix_timestamp>}
	// 用 ECDSA P-256 私钥签名后，作为 Bearer token 发送
	jwtToken := "TODO_JWT_TOKEN"

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

	if resp.StatusCode != http.StatusOK {
		log.Printf("[apns] push failed device=%s status=%d", deviceToken, resp.StatusCode)
		return fmt.Errorf("apns: unexpected status %d", resp.StatusCode)
	}

	log.Printf("[apns] push sent device=%s event=%s", deviceToken, eventType)
	return nil
}

// buildAPNsPayload 根据事件类型和摘要构建 APNs JSON payload
func buildAPNsPayload(eventType, summary string) map[string]interface{} {
	meta, ok := pushEventMap[eventType]
	// 未知事件类型使用默认值
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
