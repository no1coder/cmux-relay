package server

import (
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/manaflow-ai/cmux-relay/protocol"
	"github.com/manaflow-ai/cmux-relay/store"
)

// authTimeout 是 WebSocket 握手认证的超时时间
const authTimeout = 30 * time.Second

// authChallengeMsg 是服务端发送给客户端的认证挑战消息
type authChallengeMsg struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
}

// authClientMsg 是客户端返回的认证消息
type authClientMsg struct {
	Type      string `json:"type"`
	DeviceID  string `json:"device_id"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

// resumePayload 是 "resume" 消息的 payload 结构
type resumePayload struct {
	LastSeq uint64 `json:"last_seq"`
}

// Relay 负责 WebSocket 认证握手和消息中继
type Relay struct {
	store  *store.SQLiteStore
	router *Router
	auth   *Authenticator
	apns   *APNsClient
	seqGen atomic.Uint64
}

// NewRelay 创建 Relay 实例。apns 可以为 nil（表示未配置推送）
func NewRelay(s *store.SQLiteStore, r *Router, a *Authenticator) *Relay {
	return &Relay{store: s, router: r, auth: a}
}

// NewRelayWithAPNs 创建带 APNs 客户端的 Relay 实例
func NewRelayWithAPNs(s *store.SQLiteStore, r *Router, a *Authenticator, apns *APNsClient) *Relay {
	return &Relay{store: s, router: r, auth: a, apns: apns}
}

// HandleDeviceWS 处理 Mac 设备的 WebSocket 连接：认证 → 注册 → 消息转发
func (rl *Relay) HandleDeviceWS(conn *websocket.Conn, deviceID string) {
	defer conn.Close()

	// 限制单条消息最大 1 MB，防止超大消息耗尽内存
	conn.SetReadLimit(1 * 1024 * 1024)

	// 1. 认证握手
	secretHash, err := rl.doAuthHandshake(conn, deviceID)
	if err != nil {
		log.Printf("[relay/device] auth failed device=%s: %v", deviceID, err)
		return
	}
	_ = secretHash

	// 2. 查询配对信息，获取 phoneID
	pair, err := rl.store.LookupPairByDevice(deviceID)
	if err != nil {
		if errors.Is(err, store.ErrPairNotFound) {
			log.Printf("[relay/device] no pair found for device=%s", deviceID)
			_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "pair_not_found")) //nolint:errcheck // 连接即将关闭
		} else {
			log.Printf("[relay/device] lookup pair error device=%s: %v", deviceID, err)
		}
		return
	}

	// 3. 注册到路由表
	dc := &DeviceConn{
		Conn:     conn,
		DeviceID: deviceID,
		PairID:   pair.PhoneID,
		IsMac:    true,
	}
	rl.router.RegisterDevice(dc)
	defer rl.router.UnregisterDevice(deviceID)

	log.Printf("[relay/device] connected device=%s phone=%s", deviceID, pair.PhoneID)

	// 4. 消息转发循环
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[relay/device] read error device=%s: %v", deviceID, err)
			return
		}

		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			log.Printf("[relay/device] unmarshal error device=%s: %v", deviceID, err)
			continue
		}

		// 验证 Envelope 必填字段，并确保来源匹配（Mac 端必须发 from=mac）
		if err := env.Validate(); err != nil {
			log.Printf("[relay/device] invalid envelope device=%s: %v", deviceID, err)
			continue
		}
		if env.From != protocol.OriginMac {
			log.Printf("[relay/device] from mismatch device=%s: expected mac, got %s", deviceID, env.From)
			continue
		}

		// 转发给手机
		rl.forwardToPhone(env, deviceID, pair.PhoneID)
	}
}

// HandlePhoneWS 处理 iPhone 的 WebSocket 连接：认证 → 注册 → 消息转发
func (rl *Relay) HandlePhoneWS(conn *websocket.Conn, phoneID string) {
	defer conn.Close()

	// 限制单条消息最大 1 MB，防止超大消息耗尽内存
	conn.SetReadLimit(1 * 1024 * 1024)

	// 1. 认证握手（使用 phoneID 作为 deviceID 参数）
	_, err := rl.doAuthHandshake(conn, phoneID)
	if err != nil {
		log.Printf("[relay/phone] auth failed phone=%s: %v", phoneID, err)
		return
	}

	// 2. 查询配对信息，获取 deviceID
	pair, err := rl.store.LookupPairByPhone(phoneID)
	if err != nil {
		if errors.Is(err, store.ErrPairNotFound) {
			log.Printf("[relay/phone] no pair found for phone=%s", phoneID)
			_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "pair_not_found")) //nolint:errcheck // 连接即将关闭
		} else {
			log.Printf("[relay/phone] lookup pair error phone=%s: %v", phoneID, err)
		}
		return
	}

	// 3. 注册到路由表
	pc := &DeviceConn{
		Conn:     conn,
		DeviceID: phoneID,
		PairID:   pair.DeviceID,
		IsMac:    false,
	}
	rl.router.RegisterPhone(pc)
	defer rl.router.UnregisterPhone(phoneID)

	log.Printf("[relay/phone] connected phone=%s device=%s", phoneID, pair.DeviceID)

	// 4. 消息接收循环
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[relay/phone] read error phone=%s: %v", phoneID, err)
			return
		}

		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			log.Printf("[relay/phone] unmarshal error phone=%s: %v", phoneID, err)
			continue
		}

		// 验证 Envelope 必填字段，并确保来源匹配（Phone 端必须发 from=phone）
		if err := env.Validate(); err != nil {
			log.Printf("[relay/phone] invalid envelope phone=%s: %v", phoneID, err)
			continue
		}
		if env.From != protocol.OriginPhone {
			log.Printf("[relay/phone] from mismatch phone=%s: expected phone, got %s", phoneID, env.From)
			continue
		}

		// 处理 resume 消息：从缓冲区重放指定 seq 之后的消息
		if env.Type == protocol.TypeResume {
			rl.handleResume(conn, env, pair.DeviceID, phoneID)
			continue
		}

		// 其他消息转发给 Mac
		rl.forwardToDevice(env, pair.DeviceID, phoneID)
	}
}

// doAuthHandshake 执行认证握手流程，返回 secretHash
// 流程：发送 challenge → 接收 auth → 验证 HMAC + nonce → 发送 auth_ok/auth_failed
func (rl *Relay) doAuthHandshake(conn *websocket.Conn, clientID string) (string, error) {
	// 设置认证超时
	if err := conn.SetReadDeadline(time.Now().Add(authTimeout)); err != nil {
		return "", err
	}
	defer func() {
		// 清除 deadline，恢复正常读取
		_ = conn.SetReadDeadline(time.Time{})
	}()

	// 1. 生成并发送 challenge（设置写超时防止慢客户端阻塞）
	nonce, err := GenerateNonce()
	if err != nil {
		return "", err
	}
	challenge := authChallengeMsg{Type: "auth_challenge", Nonce: nonce}
	if err := conn.SetWriteDeadline(time.Now().Add(authTimeout)); err != nil {
		return "", err
	}
	if err := conn.WriteJSON(challenge); err != nil {
		return "", err
	}
	_ = conn.SetWriteDeadline(time.Time{}) // 清除写超时

	// 2. 接收客户端 auth 消息
	_, data, err := conn.ReadMessage()
	if err != nil {
		return "", err
	}
	var clientMsg authClientMsg
	if err := json.Unmarshal(data, &clientMsg); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", err
	}
	if clientMsg.Type != "auth" {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", errors.New("expected auth message")
	}

	// 3. 查询配对记录，获取 secretHash
	secretHash, err := rl.lookupSecretHash(clientID)
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", err
	}

	// 4. 验证 HMAC 签名
	if err := rl.auth.Verify(clientMsg.DeviceID, clientMsg.Nonce, clientMsg.Timestamp, clientMsg.Signature, secretHash); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", err
	}

	// 5. 原子化标记 nonce 已使用（同时完成查重和标记，防重放攻击竞态）
	// 使用服务端时间计算过期时间，防止客户端伪造时间戳延长 nonce 有效期
	nonceExpiresAt := time.Now().Unix() + 60
	firstUse, err := rl.store.TryMarkNonce(clientMsg.Nonce, nonceExpiresAt)
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", err
	}
	if !firstUse {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", errors.New("nonce already used")
	}

	// 6. 发送 auth_ok（设置写超时防止慢客户端阻塞）
	if err := conn.SetWriteDeadline(time.Now().Add(authTimeout)); err != nil {
		return "", err
	}
	if err := conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_ok")); err != nil {
		return "", err
	}
	_ = conn.SetWriteDeadline(time.Time{}) // 清除写超时

	return secretHash, nil
}

// lookupSecretHash 根据 clientID 查询 secretHash（先尝试 device，再尝试 phone）
func (rl *Relay) lookupSecretHash(clientID string) (string, error) {
	pair, err := rl.store.LookupPairByDevice(clientID)
	if err == nil {
		return pair.SecretHash, nil
	}
	pair, err = rl.store.LookupPairByPhone(clientID)
	if err == nil {
		return pair.SecretHash, nil
	}
	return "", errors.New("no pair found for client: " + clientID)
}

// handleResume 处理 resume 消息，从缓冲区重放指定 seq 之后的消息给 Phone
func (rl *Relay) handleResume(conn *websocket.Conn, env protocol.Envelope, deviceID, phoneID string) {
	var payload resumePayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		log.Printf("[relay] invalid resume payload phone=%s: %v", phoneID, err)
		return
	}

	buf := rl.router.GetOrCreateBuffer(deviceID, phoneID)
	// 注意：handleResume 通过 pc 指针调用，需要加写锁
	pc := rl.router.GetPhone(phoneID)
	if pc == nil {
		return
	}
	msgs := buf.ReplaySince(payload.LastSeq, 100)
	for _, msg := range msgs {
		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		if err := pc.SafeWrite(websocket.TextMessage, data); err != nil {
			log.Printf("[relay] replay write error phone=%s: %v", phoneID, err)
			return
		}
	}
	log.Printf("[relay] replayed %d messages to phone=%s since seq=%d", len(msgs), phoneID, payload.LastSeq)
}

// forwardToPhone 将消息分配 seq，存入缓冲区，然后发送给在线 Phone
// 若 Phone 不在线且事件类型需要推送，则尝试通过 APNs 发送推送通知
func (rl *Relay) forwardToPhone(env protocol.Envelope, deviceID, phoneID string) {
	// 分配单调递增 seq
	seq := rl.seqGen.Add(1)
	env.Seq = seq

	// 写入环形缓冲区（screen_snapshot 类型会被 RingBuffer 自动过滤）
	buf := rl.router.GetOrCreateBuffer(deviceID, phoneID)
	buf.Push(env)

	// 阶段事件始终触发 Live Activity 更新（不管手机是否在线）
	if env.Type == protocol.TypeEvent {
		go rl.handlePhaseEvent(env, phoneID)
	}

	// 发送给在线 Phone
	pc := rl.router.GetPhone(phoneID)
	if pc == nil {
		// Phone 不在线，尝试 APNs 推送
		rl.tryAPNsPush(env, phoneID)
		return
	}
	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("[relay] marshal error forwarding to phone=%s: %v", phoneID, err)
		return
	}
	if err := pc.SafeWrite(websocket.TextMessage, data); err != nil {
		log.Printf("[relay] write error to phone=%s: %v", phoneID, err)
	}
}

// tryAPNsPush 在 Phone 不在线时，检查是否需要推送并发送 APNs 通知。
// 对于 E2E 加密消息，使用信封中的 push_hint 明文字段进行推送路由。
func (rl *Relay) tryAPNsPush(env protocol.Envelope, phoneID string) {
	// APNs 客户端未配置
	if rl.apns == nil {
		return
	}

	// 确定推送的事件类型和摘要
	var eventType, summary string

	if env.IsE2E() {
		// E2E 加密消息：payload 不可解析，依赖 push_hint 明文字段
		if env.PushHintData == nil {
			// 没有 push_hint，不推送
			return
		}
		eventType = env.PushHintData.Event
		summary = env.PushHintData.Summary
		if !shouldPush(eventType) {
			return
		}
	} else {
		// 非加密消息：优先使用 push_hint，否则尝试从 payload 中解析事件子类型
		if env.PushHintData != nil {
			eventType = env.PushHintData.Event
			summary = env.PushHintData.Summary
		} else {
			// 尝试从 payload 中提取业务事件子类型
			var payloadMap map[string]interface{}
			if err := json.Unmarshal(env.Payload, &payloadMap); err == nil {
				if evt, ok := payloadMap["event"].(string); ok {
					eventType = evt
				}
				if sum, ok := payloadMap["summary"].(string); ok {
					summary = sum
				}
			}
			if eventType == "" {
				eventType = string(env.Type)
			}
			if summary == "" {
				summary = pushSummaryForType(eventType)
			}
		}
		if !shouldPush(eventType) {
			return
		}
	}

	// 截断 summary，防止推送内容过长
	if len(summary) > 100 {
		summary = summary[:100]
	}

	// 查询配对记录，获取 APNs token
	pair, err := rl.store.LookupPairByPhone(phoneID)
	if err != nil {
		log.Printf("[relay] apns lookup pair error phone=%s: %v", phoneID, err)
		return
	}
	if pair.APNsToken == "" {
		return
	}

	if err := rl.apns.SendPush(pair.APNsToken, eventType, summary); err != nil {
		log.Printf("[relay] apns send push error phone=%s: %v", phoneID, err)
	}
}

// handlePhaseEvent 处理 phase.update 事件，触发 Live Activity 更新和 APNs 推送
func (rl *Relay) handlePhaseEvent(env protocol.Envelope, phoneID string) {
	if rl.apns == nil {
		return
	}

	// 解析 payload 提取事件信息
	var payload map[string]interface{}
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		return
	}

	eventName, _ := payload["event"].(string)
	if eventName != "phase.update" {
		return
	}

	phase, _ := payload["phase"].(string)
	if phase == "" {
		return
	}

	// 1. 更新 Live Activity
	laToken, err := rl.store.LookupLiveActivityToken(phoneID)
	if err == nil && laToken != "" {
		contentState := map[string]interface{}{
			"activeSessionId":      payload["surface_id"],
			"projectName":          payload["project_name"],
			"phase":                phase,
			"toolName":             payload["tool_name"],
			"lastUserMessage":      payload["last_user_message"],
			"lastAssistantSummary": payload["last_assistant_summary"],
			"totalSessions":        1,
			"activeSessions":       1,
			"startedAt":            float64(time.Now().Unix()),
		}

		event := "update"
		if phase == "ended" {
			event = "end"
		}

		if err := rl.apns.SendLiveActivityUpdate(laToken, contentState, event); err != nil {
			log.Printf("[relay] live activity update failed phone=%s: %v", phoneID[:10], err)
			// 终端错误时清除 token
			if isTerminalAPNsError(err) {
				_ = rl.store.UpdateLiveActivityToken(phoneID, "")
				log.Printf("[relay] cleared invalid LA token phone=%s", phoneID[:10])
			}
		}
	}

	// 2. 发送 APNs 推送通知（仅特定阶段）
	switch phase {
	case "ended":
		summary, _ := payload["last_assistant_summary"].(string)
		if summary == "" {
			summary = "Claude 已完成"
		}
		rl.apns.SendPush(rl.lookupAPNsToken(phoneID), "task_complete", summary) //nolint:errcheck
	case "waiting_approval":
		toolName, _ := payload["tool_name"].(string)
		summary := "需要审批"
		if toolName != "" {
			summary = "需要审批: " + toolName
		}
		rl.apns.SendPush(rl.lookupAPNsToken(phoneID), "approval_required", summary) //nolint:errcheck
	case "error":
		rl.apns.SendPush(rl.lookupAPNsToken(phoneID), "task_failed", "执行出错") //nolint:errcheck
	}
}

// lookupAPNsToken 查找 APNs push token
func (rl *Relay) lookupAPNsToken(phoneID string) string {
	pair, err := rl.store.LookupPairByPhone(phoneID)
	if err != nil {
		return ""
	}
	return pair.APNsToken
}

// isTerminalAPNsError 检测 APNs 终端错误（token 永久失效）
func isTerminalAPNsError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "status=410") ||
		strings.Contains(s, "BadDeviceToken") ||
		strings.Contains(s, "DeviceTokenNotForTopic")
}

// forwardToDevice 将消息发送给在线 Mac 设备。
// 当 Phone 发起 RPC 请求但目标 Mac 不在线时，立即回送结构化 rpc_response，
// 避免客户端只能靠超时推断失败。
func (rl *Relay) forwardToDevice(env protocol.Envelope, deviceID string, phoneID string) {
	dc := rl.router.GetDevice(deviceID)
	if dc == nil {
		if env.From == protocol.OriginPhone && env.Type == protocol.TypeRPCRequest && phoneID != "" {
			rl.respondDeviceOffline(env, phoneID, deviceID)
		}
		return
	}
	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("[relay] marshal error forwarding to device=%s: %v", deviceID, err)
		return
	}
	if err := dc.SafeWrite(websocket.TextMessage, data); err != nil {
		log.Printf("[relay] write error to device=%s: %v", deviceID, err)
	}
}

// respondDeviceOffline 向 phone 直接回送"设备离线"的合成 rpc_response。
// 注意：该合成响应不写入环形缓冲区——否则 phone 离线重连触发 resume 重放时，
// 会用这条过时的 offline 错误覆盖 mac 已上线后返回的真实结果。
// 因此这里绕开 forwardToPhone（那条路径包含 buf.Push），直接向当前在线的 phone 连接写入。
// 若 phone 此刻也不在线，则静默丢弃：phone 重连后会自然超时/重发请求。
func (rl *Relay) respondDeviceOffline(env protocol.Envelope, phoneID string, deviceID string) {
	var requestPayload map[string]interface{}
	if err := json.Unmarshal(env.Payload, &requestPayload); err != nil {
		log.Printf("[relay] invalid rpc request payload from phone=%s for offline device: %v", phoneID, err)
		return
	}

	requestID, ok := requestPayload["id"]
	if !ok {
		log.Printf("[relay] rpc request missing id from phone=%s for offline device", phoneID)
		return
	}

	method, _ := requestPayload["method"].(string)
	// 不把内部 deviceID 写入响应 message，避免向 phone 端泄露
	payload := map[string]interface{}{
		"id":      requestID,
		"error":   "device_offline",
		"message": "mac device is offline",
		"method":  method,
	}

	// 仍分配 seq 以保持响应序号语义（phone 侧可用它判断新鲜度）
	seq := rl.seqGen.Add(1)
	responseEnv := protocol.Envelope{
		Ts:      time.Now().UnixMilli(),
		From:    protocol.OriginMac,
		Type:    protocol.TypeRPCResponse,
		Seq:     seq,
		Payload: mustMarshalRaw(payload),
	}

	pc := rl.router.GetPhone(phoneID)
	if pc == nil {
		// phone 离线：不 push 到 buffer，避免日后重放这条过期错误
		log.Printf("[relay] synthetic offline response dropped: phone=%s not online for offline device=%s", phoneID, deviceID)
		return
	}
	data, err := json.Marshal(responseEnv)
	if err != nil {
		log.Printf("[relay] marshal synthetic offline response error phone=%s: %v", phoneID, err)
		return
	}
	if err := pc.SafeWrite(websocket.TextMessage, data); err != nil {
		log.Printf("[relay] write synthetic offline response error phone=%s: %v", phoneID, err)
	}
}

func mustMarshalRaw(value interface{}) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		log.Printf("[relay] marshal synthetic payload error: %v", err)
		return json.RawMessage(`{"error":"internal_error","message":"failed to marshal synthetic payload"}`)
	}
	return data
}

// marshalSimple 序列化一个简单的 {"key":"value"} 消息
func marshalSimple(key, value string) []byte {
	data, _ := json.Marshal(map[string]string{key: value})
	return data
}

// pushSummaryForType 根据事件类型返回固定的描述文本，避免将原始 payload 暴露到推送通知
func pushSummaryForType(eventType string) string {
	switch eventType {
	case "approval_required":
		return "需要您审批操作"
	case "task_complete":
		return "任务已完成"
	case "task_failed":
		return "任务执行失败"
	case "terminal_exit":
		return "终端进程已退出"
	case "notification":
		return "终端命令完成"
	default:
		return "您有新的通知"
	}
}
