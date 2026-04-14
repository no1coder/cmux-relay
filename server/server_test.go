package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/manaflow-ai/cmux-relay/protocol"
)

// ---- 测试辅助函数 ----

// testSHA256Hex 计算字符串的 SHA256（十六进制），与 auth.go 中的 sha256Hash 等价
func testSHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// testComputeHMAC 计算 HMAC-SHA256 签名，与 auth.go 中的 computeHMACHex 等价
// key = SHA256(pair_secret)（hex 字符串），message = deviceID:nonce:timestamp（冒号分隔）
func testComputeHMAC(secret, deviceID, nonce string, ts int64) string {
	secretHash := testSHA256Hex(secret)
	mac := hmac.New(sha256.New, []byte(secretHash))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d", deviceID, nonce, ts)))
	return hex.EncodeToString(mac.Sum(nil))
}

// testHTTPPost 向 url 发送 JSON POST 请求并返回解码后的响应 map
func testHTTPPost(t *testing.T, url, body string) map[string]interface{} {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST %s 失败: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("POST %s 返回非 2xx 状态码: %d", url, resp.StatusCode)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("解码响应 JSON 失败: %v", err)
	}
	return result
}

// testAuthenticateWS 完成 WebSocket 认证握手：
//  1. 读取 auth_challenge，提取 nonce
//  2. 用 testComputeHMAC 计算签名
//  3. 发送 auth 消息
//  4. 读取 auth_ok
func testAuthenticateWS(t *testing.T, conn *websocket.Conn, id, secret string) {
	t.Helper()

	// 设置读取超时，避免挂起
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 读取 auth_challenge
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("读取 auth_challenge 失败: %v", err)
	}
	var challenge map[string]string
	if err := json.Unmarshal(data, &challenge); err != nil {
		t.Fatalf("解析 auth_challenge 失败: %v", err)
	}
	if challenge["type"] != "auth_challenge" {
		t.Fatalf("期望 auth_challenge，实际得到: %s", challenge["type"])
	}
	nonce := challenge["nonce"]
	if nonce == "" {
		t.Fatal("auth_challenge 中 nonce 为空")
	}

	// 计算签名
	ts := time.Now().Unix()
	sig := testComputeHMAC(secret, id, nonce, ts)

	// 发送 auth 消息
	authMsg := map[string]interface{}{
		"type":      "auth",
		"device_id": id,
		"nonce":     nonce,
		"timestamp": ts,
		"signature": sig,
	}
	if err := conn.WriteJSON(authMsg); err != nil {
		t.Fatalf("发送 auth 消息失败: %v", err)
	}

	// 读取 auth_ok
	_, data, err = conn.ReadMessage()
	if err != nil {
		t.Fatalf("读取 auth 响应失败: %v", err)
	}
	var resp map[string]string
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("解析 auth 响应失败: %v", err)
	}
	if resp["type"] != "auth_ok" {
		t.Fatalf("期望 auth_ok，实际得到: %s", resp["type"])
	}

	// 清除读取 deadline，恢复正常读取
	conn.SetReadDeadline(time.Time{})
}

// testPairDeviceAndPhone 完成配对流程并返回 pair_secret
func testPairDeviceAndPhone(t *testing.T, baseURL, deviceID, phoneID string) string {
	t.Helper()

	// 步骤 1：POST /api/pair/init，获取 pair_token
	initResp := testHTTPPost(t, baseURL+"/api/pair/init",
		fmt.Sprintf(`{"device_id":"%s","device_name":"Test Mac"}`, deviceID))
	pairToken, ok := initResp["pair_token"].(string)
	if !ok || pairToken == "" {
		t.Fatalf("pair/init 未返回 pair_token，响应: %v", initResp)
	}

	// 步骤 2：POST /api/pair/confirm，完成配对，获取 pair_secret
	confirmResp := testHTTPPost(t, baseURL+"/api/pair/confirm",
		fmt.Sprintf(`{"pair_token":"%s","phone_id":"%s","phone_name":"Test iPhone"}`,
			pairToken, phoneID))
	pairSecret, ok := confirmResp["pair_secret"].(string)
	if !ok || pairSecret == "" {
		t.Fatalf("pair/confirm 未返回 pair_secret，响应: %v", confirmResp)
	}

	return pairSecret
}

// testConnectWS 连接到 WebSocket 并完成认证握手，返回连接对象
func testConnectWS(t *testing.T, wsURL, id, secret string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WebSocket 连接 %s 失败: %v", wsURL, err)
	}
	testAuthenticateWS(t, conn, id, secret)
	return conn
}

// ---- 测试用例 ----

// TestHealthEndpoint 验证 /health 返回 200 + {"ok":true}
func TestHealthEndpoint(t *testing.T) {
	srv, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("创建 server 失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("期望状态码 200，实际得到 %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v", err)
	}
	if body["ok"] != true {
		t.Errorf("期望 {\"ok\":true}，实际得到 %v", body)
	}
}

// TestEndToEnd_PairAndRelay 验证完整的配对 + 双向消息中继流程
func TestEndToEnd_PairAndRelay(t *testing.T) {
	// 1. 创建使用内存数据库的 server
	srv, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("创建 server 失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	deviceID := "mac-test-1"
	phoneID := "phone-test-1"

	// 2. 完成配对流程
	pairSecret := testPairDeviceAndPhone(t, ts.URL, deviceID, phoneID)

	// 3. Mac 连接到 /ws/device/mac-test-1 并完成认证握手
	macConn := testConnectWS(t, wsURL+"/ws/device/"+deviceID, deviceID, pairSecret)
	defer macConn.Close()

	// 4. Phone 连接到 /ws/phone/phone-test-1 并完成认证握手
	phoneConn := testConnectWS(t, wsURL+"/ws/phone/"+phoneID, phoneID, pairSecret)
	defer phoneConn.Close()

	// 给路由表一点时间完成注册
	time.Sleep(50 * time.Millisecond)

	// 5. Phone 发送 rpc_request（method=ping）给 Mac
	payload := `{"method":"ping","id":1}`
	phoneMsg := protocol.Envelope{
		Ts:      time.Now().UnixMilli(),
		From:    protocol.OriginPhone,
		Type:    protocol.TypeRPCRequest,
		Payload: json.RawMessage(payload),
	}
	if err := phoneConn.WriteJSON(phoneMsg); err != nil {
		t.Fatalf("Phone 发送消息失败: %v", err)
	}

	// 6. Mac 应接收到该消息，验证 payload.method == "ping"
	macConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := macConn.ReadMessage()
	if err != nil {
		t.Fatalf("Mac 读取消息失败: %v", err)
	}
	macConn.SetReadDeadline(time.Time{})

	var receivedEnv protocol.Envelope
	if err := json.Unmarshal(data, &receivedEnv); err != nil {
		t.Fatalf("Mac 解析消息失败: %v", err)
	}
	if receivedEnv.Type != protocol.TypeRPCRequest {
		t.Errorf("期望消息类型 %s，实际得到 %s", protocol.TypeRPCRequest, receivedEnv.Type)
	}
	var receivedPayload map[string]interface{}
	if err := json.Unmarshal(receivedEnv.Payload, &receivedPayload); err != nil {
		t.Fatalf("解析 payload 失败: %v", err)
	}
	if receivedPayload["method"] != "ping" {
		t.Errorf("期望 method=ping，实际得到 %v", receivedPayload["method"])
	}

	// 7. Mac 发送 rpc_response 回复 Phone
	respPayload := `{"result":"pong","id":1}`
	macMsg := protocol.Envelope{
		Ts:      time.Now().UnixMilli(),
		From:    protocol.OriginMac,
		Type:    protocol.TypeRPCResponse,
		Payload: json.RawMessage(respPayload),
	}
	if err := macConn.WriteJSON(macMsg); err != nil {
		t.Fatalf("Mac 发送响应失败: %v", err)
	}

	// 8. Phone 应接收到带有 seq 号的响应
	phoneConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err = phoneConn.ReadMessage()
	if err != nil {
		t.Fatalf("Phone 读取响应失败: %v", err)
	}
	phoneConn.SetReadDeadline(time.Time{})

	var phoneReceivedEnv protocol.Envelope
	if err := json.Unmarshal(data, &phoneReceivedEnv); err != nil {
		t.Fatalf("Phone 解析响应失败: %v", err)
	}
	if phoneReceivedEnv.Type != protocol.TypeRPCResponse {
		t.Errorf("期望消息类型 %s，实际得到 %s", protocol.TypeRPCResponse, phoneReceivedEnv.Type)
	}
	// 验证服务端已分配 seq 号
	if phoneReceivedEnv.Seq == 0 {
		t.Error("期望服务端分配 seq > 0，实际 seq = 0")
	}
}

// TestPhoneRPCToOfflineMacGetsImmediateError 验证当 Phone 发起 rpc_request 但 Mac 不在线时，
// relay 会立刻返回结构化 rpc_response，而不是让客户端一直等到超时。
func TestPhoneRPCToOfflineMacGetsImmediateError(t *testing.T) {
	srv, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("创建 server 失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	deviceID := "mac-offline-test"
	phoneID := "phone-offline-test"

	pairSecret := testPairDeviceAndPhone(t, ts.URL, deviceID, phoneID)

	phoneConn := testConnectWS(t, wsURL+"/ws/phone/"+phoneID, phoneID, pairSecret)
	defer phoneConn.Close()

	time.Sleep(50 * time.Millisecond)

	payload := `{"method":"surface.list","id":7,"params":{}}`
	phoneMsg := protocol.Envelope{
		Ts:      time.Now().UnixMilli(),
		From:    protocol.OriginPhone,
		Type:    protocol.TypeRPCRequest,
		Payload: json.RawMessage(payload),
	}
	if err := phoneConn.WriteJSON(phoneMsg); err != nil {
		t.Fatalf("Phone 发送消息失败: %v", err)
	}

	phoneConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := phoneConn.ReadMessage()
	if err != nil {
		t.Fatalf("Phone 读取响应失败: %v", err)
	}
	phoneConn.SetReadDeadline(time.Time{})

	var receivedEnv protocol.Envelope
	if err := json.Unmarshal(data, &receivedEnv); err != nil {
		t.Fatalf("Phone 解析响应失败: %v", err)
	}
	if receivedEnv.Type != protocol.TypeRPCResponse {
		t.Fatalf("期望 rpc_response，实际得到 %s", receivedEnv.Type)
	}
	if receivedEnv.Seq == 0 {
		t.Fatal("期望 relay 为离线错误响应分配 seq > 0")
	}

	var receivedPayload map[string]interface{}
	if err := json.Unmarshal(receivedEnv.Payload, &receivedPayload); err != nil {
		t.Fatalf("解析 payload 失败: %v", err)
	}
	if got := receivedPayload["error"]; got != "device_offline" {
		t.Fatalf("期望 error=device_offline，实际得到 %v", got)
	}
	if got := receivedPayload["method"]; got != "surface.list" {
		t.Fatalf("期望 method=surface.list，实际得到 %v", got)
	}
	if got := receivedPayload["id"]; got != float64(7) {
		t.Fatalf("期望 id=7，实际得到 %v", got)
	}
	// 断言合成响应的 message 不泄露内部 deviceID
	msg, _ := receivedPayload["message"].(string)
	if msg == "" {
		t.Fatal("期望 message 字段非空")
	}
	if strings.Contains(msg, deviceID) {
		t.Fatalf("message 不应包含内部 deviceID，实际: %q", msg)
	}
}

// TestOfflineSyntheticResponseNotBuffered 验证当 mac 离线、合成 device_offline 响应发给 phone 后，
// 该响应不会被写入环形缓冲区——否则 phone 离线重连 resume 时会重放这条过期错误，
// 覆盖 mac 上线后返回的真实结果。
func TestOfflineSyntheticResponseNotBuffered(t *testing.T) {
	srv, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("创建 server 失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	deviceID := "mac-offline-buf"
	phoneID := "phone-offline-buf"

	pairSecret := testPairDeviceAndPhone(t, ts.URL, deviceID, phoneID)

	// 第一次：phone 连接，mac 不在线，触发合成 offline 响应
	phoneConn := testConnectWS(t, wsURL+"/ws/phone/"+phoneID, phoneID, pairSecret)

	time.Sleep(50 * time.Millisecond)

	reqPayload := `{"method":"surface.list","id":42,"params":{}}`
	if err := phoneConn.WriteJSON(protocol.Envelope{
		Ts:      time.Now().UnixMilli(),
		From:    protocol.OriginPhone,
		Type:    protocol.TypeRPCRequest,
		Payload: json.RawMessage(reqPayload),
	}); err != nil {
		t.Fatalf("Phone 发送消息失败: %v", err)
	}

	// 读取合成 offline 响应，记录其 seq
	phoneConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := phoneConn.ReadMessage()
	if err != nil {
		t.Fatalf("Phone 读取合成响应失败: %v", err)
	}
	phoneConn.SetReadDeadline(time.Time{})

	var offlineEnv protocol.Envelope
	if err := json.Unmarshal(data, &offlineEnv); err != nil {
		t.Fatalf("解析合成响应失败: %v", err)
	}
	if offlineEnv.Type != protocol.TypeRPCResponse {
		t.Fatalf("期望 rpc_response，实际 %s", offlineEnv.Type)
	}

	// phone 断开，稍后重连并发 resume(last_seq=0)
	phoneConn.Close()
	time.Sleep(100 * time.Millisecond)

	phoneConn2 := testConnectWS(t, wsURL+"/ws/phone/"+phoneID, phoneID, pairSecret)
	defer phoneConn2.Close()

	time.Sleep(50 * time.Millisecond)

	resumePayloadJSON, _ := json.Marshal(map[string]interface{}{"last_seq": 0})
	if err := phoneConn2.WriteJSON(protocol.Envelope{
		Ts:      time.Now().UnixMilli(),
		From:    protocol.OriginPhone,
		Type:    protocol.TypeResume,
		Payload: resumePayloadJSON,
	}); err != nil {
		t.Fatalf("Phone 发送 resume 失败: %v", err)
	}

	// 在 500ms 内收集所有重放消息；期望 0 条——buffer 中不应有合成 offline 响应
	phoneConn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var replayed []protocol.Envelope
	for {
		_, d, rerr := phoneConn2.ReadMessage()
		if rerr != nil {
			break
		}
		var e protocol.Envelope
		if uerr := json.Unmarshal(d, &e); uerr != nil {
			continue
		}
		replayed = append(replayed, e)
	}
	phoneConn2.SetReadDeadline(time.Time{})

	for _, e := range replayed {
		if e.Type == protocol.TypeRPCResponse {
			var p map[string]interface{}
			_ = json.Unmarshal(e.Payload, &p)
			if p["error"] == "device_offline" {
				t.Fatalf("合成的 device_offline 响应不应被重放（buffered），got seq=%d payload=%v", e.Seq, p)
			}
		}
	}
}

// TestEndToEnd_AuthFail 验证错误的 pair_secret 导致 auth_failed
func TestEndToEnd_AuthFail(t *testing.T) {
	srv, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("创建 server 失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	deviceID := "mac-auth-fail"
	phoneID := "phone-auth-fail"

	// 完成配对流程（得到正确的 pairSecret，但下面故意用错误的）
	testPairDeviceAndPhone(t, ts.URL, deviceID, phoneID)

	// 尝试用错误的 secret 连接
	wrongSecret := "this-is-definitely-wrong-secret"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"/ws/device/"+deviceID, nil)
	if err != nil {
		t.Fatalf("WebSocket 连接失败: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 读取 auth_challenge
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("读取 auth_challenge 失败: %v", err)
	}
	var challenge map[string]string
	if err := json.Unmarshal(data, &challenge); err != nil {
		t.Fatalf("解析 auth_challenge 失败: %v", err)
	}
	if challenge["type"] != "auth_challenge" {
		t.Fatalf("期望 auth_challenge，实际得到: %s", challenge["type"])
	}
	nonce := challenge["nonce"]

	// 用错误的 secret 计算签名
	ts2 := time.Now().Unix()
	wrongSig := testComputeHMAC(wrongSecret, deviceID, nonce, ts2)

	authMsg := map[string]interface{}{
		"type":      "auth",
		"device_id": deviceID,
		"nonce":     nonce,
		"timestamp": ts2,
		"signature": wrongSig,
	}
	if err := conn.WriteJSON(authMsg); err != nil {
		t.Fatalf("发送 auth 消息失败: %v", err)
	}

	// 应接收到 auth_failed
	_, data, err = conn.ReadMessage()
	if err != nil {
		// 服务端也可能直接关闭连接
		return
	}
	var resp map[string]string
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if resp["type"] != "auth_failed" {
		t.Errorf("期望 auth_failed，实际得到: %s", resp["type"])
	}
}

// TestEndToEnd_ResumeAfterReconnect 验证 Phone 断线重连后可通过 resume 补收缺失消息
func TestEndToEnd_ResumeAfterReconnect(t *testing.T) {
	srv, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("创建 server 失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	deviceID := "mac-resume-1"
	phoneID := "phone-resume-1"

	// 1. 完成配对
	pairSecret := testPairDeviceAndPhone(t, ts.URL, deviceID, phoneID)

	// 2. 连接 Mac 和 Phone
	macConn := testConnectWS(t, wsURL+"/ws/device/"+deviceID, deviceID, pairSecret)
	defer macConn.Close()

	phoneConn1 := testConnectWS(t, wsURL+"/ws/phone/"+phoneID, phoneID, pairSecret)

	// 给路由表一点时间完成注册
	time.Sleep(50 * time.Millisecond)

	// 3. Mac 发送 5 条消息，Phone 接收并记录最后一个 seq
	var lastSeq uint64
	for i := 0; i < 5; i++ {
		payload := fmt.Sprintf(`{"index":%d}`, i)
		msg := protocol.Envelope{
			Ts:      time.Now().UnixMilli(),
			From:    protocol.OriginMac,
			Type:    protocol.TypeRPCRequest,
			Payload: json.RawMessage(payload),
		}
		if err := macConn.WriteJSON(msg); err != nil {
			t.Fatalf("Mac 发送消息 %d 失败: %v", i, err)
		}

		// Phone 读取消息
		phoneConn1.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, data, err := phoneConn1.ReadMessage()
		if err != nil {
			t.Fatalf("Phone 读取消息 %d 失败: %v", i, err)
		}
		phoneConn1.SetReadDeadline(time.Time{})

		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("Phone 解析消息 %d 失败: %v", i, err)
		}
		lastSeq = env.Seq
	}

	if lastSeq == 0 {
		t.Fatal("lastSeq 应大于 0")
	}

	// 4. Phone 断开连接
	phoneConn1.Close()
	time.Sleep(100 * time.Millisecond)

	// 5. Mac 在 Phone 离线期间再发 3 条消息
	for i := 5; i < 8; i++ {
		payload := fmt.Sprintf(`{"index":%d}`, i)
		msg := protocol.Envelope{
			Ts:      time.Now().UnixMilli(),
			From:    protocol.OriginMac,
			Type:    protocol.TypeRPCRequest,
			Payload: json.RawMessage(payload),
		}
		if err := macConn.WriteJSON(msg); err != nil {
			t.Fatalf("Mac 发送离线消息 %d 失败: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 6. Phone 重新连接并完成认证
	phoneConn2 := testConnectWS(t, wsURL+"/ws/phone/"+phoneID, phoneID, pairSecret)
	defer phoneConn2.Close()

	time.Sleep(50 * time.Millisecond)

	// 7. Phone 发送 resume 消息，携带上次已收到的 lastSeq
	resumePayload := fmt.Sprintf(`{"last_seq":%d}`, lastSeq)
	resumeMsg := protocol.Envelope{
		Ts:      time.Now().UnixMilli(),
		From:    protocol.OriginPhone,
		Type:    protocol.TypeResume,
		Payload: json.RawMessage(resumePayload),
	}
	if err := phoneConn2.WriteJSON(resumeMsg); err != nil {
		t.Fatalf("Phone 发送 resume 消息失败: %v", err)
	}

	// 8. Phone 应收到 3 条补发消息（seq > lastSeq）
	receivedCount := 0
	for receivedCount < 3 {
		phoneConn2.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, data, err := phoneConn2.ReadMessage()
		if err != nil {
			break
		}
		phoneConn2.SetReadDeadline(time.Time{})

		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("Phone 解析补发消息失败: %v", err)
		}
		if env.Seq <= lastSeq {
			t.Errorf("收到 seq=%d，期望 seq > %d", env.Seq, lastSeq)
		}
		receivedCount++
	}

	if receivedCount != 3 {
		t.Errorf("期望收到 3 条补发消息，实际收到 %d 条", receivedCount)
	}
}
