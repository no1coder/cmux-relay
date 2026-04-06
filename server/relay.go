package server

import (
	"encoding/json"
	"errors"
	"log"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/manaflow-ai/cmux-relay/protocol"
	"github.com/manaflow-ai/cmux-relay/store"
)

// authTimeout 是 WebSocket 握手认证的超时时间
const authTimeout = 10 * time.Second

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
			_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "pair_not_found"))
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

		// 转发给手机
		rl.forwardToPhone(env, deviceID, pair.PhoneID)
	}
}

// HandlePhoneWS 处理 iPhone 的 WebSocket 连接：认证 → 注册 → 消息转发
func (rl *Relay) HandlePhoneWS(conn *websocket.Conn, phoneID string) {
	defer conn.Close()

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
			_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "pair_not_found"))
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

		// 处理 resume 消息：从缓冲区重放指定 seq 之后的消息
		if env.Type == protocol.TypeResume {
			rl.handleResume(conn, env, pair.DeviceID, phoneID)
			continue
		}

		// 其他消息转发给 Mac
		rl.forwardToDevice(env, pair.DeviceID)
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

	// 1. 生成并发送 challenge
	nonce, err := GenerateNonce()
	if err != nil {
		return "", err
	}
	challenge := authChallengeMsg{Type: "auth_challenge", Nonce: nonce}
	if err := conn.WriteJSON(challenge); err != nil {
		return "", err
	}

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

	// 4. 检查 nonce 是否已被使用（防重放）
	used, err := rl.store.IsNonceUsed(clientMsg.Nonce)
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", err
	}
	if used {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", errors.New("nonce already used")
	}

	// 5. 验证 HMAC 签名
	if err := rl.auth.Verify(clientMsg.DeviceID, clientMsg.Nonce, clientMsg.Timestamp, clientMsg.Signature, secretHash); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_failed"))
		return "", err
	}

	// 6. 标记 nonce 已使用
	ts := time.Unix(clientMsg.Timestamp, 0)
	if err := rl.store.MarkNonceUsed(clientMsg.Nonce, ts); err != nil {
		log.Printf("[relay] MarkNonceUsed error: %v", err)
		// 非致命错误，继续
	}

	// 7. 发送 auth_ok
	if err := conn.WriteMessage(websocket.TextMessage, marshalSimple("type", "auth_ok")); err != nil {
		return "", err
	}

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
	msgs := buf.ReplaySince(payload.LastSeq, 100)
	for _, msg := range msgs {
		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
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
	if err := pc.Conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("[relay] write error to phone=%s: %v", phoneID, err)
	}
}

// tryAPNsPush 在 Phone 不在线时，检查是否需要推送并发送 APNs 通知
func (rl *Relay) tryAPNsPush(env protocol.Envelope, phoneID string) {
	// 检查事件类型是否需要推送
	if !shouldPush(string(env.Type)) {
		return
	}
	// APNs 客户端未配置
	if rl.apns == nil {
		return
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

	// 提取摘要（payload 的前 200 字节作为摘要）
	summary := string(env.Payload)
	if len(summary) > 200 {
		summary = summary[:200]
	}

	if err := rl.apns.SendPush(pair.APNsToken, string(env.Type), summary); err != nil {
		log.Printf("[relay] apns send push error phone=%s: %v", phoneID, err)
	}
}

// forwardToDevice 将消息发送给在线 Mac 设备
func (rl *Relay) forwardToDevice(env protocol.Envelope, deviceID string) {
	dc := rl.router.GetDevice(deviceID)
	if dc == nil {
		return
	}
	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("[relay] marshal error forwarding to device=%s: %v", deviceID, err)
		return
	}
	if err := dc.Conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("[relay] write error to device=%s: %v", deviceID, err)
	}
}

// marshalSimple 序列化一个简单的 {"key":"value"} 消息
func marshalSimple(key, value string) []byte {
	data, _ := json.Marshal(map[string]string{key: value})
	return data
}
