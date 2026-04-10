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
)

// newTestPairHandler 创建用于测试的 PairHandler（内存数据库）
func newTestPairHandler(t *testing.T) (*PairHandler, *Router) {
	t.Helper()
	srv, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("创建测试 server 失败: %v", err)
	}
	return srv.pairing, srv.router
}

// testPairHandlerPost 向 PairHandler 发送 POST 请求，返回状态码和 JSON body
func testPairHandlerPost(t *testing.T, handler http.HandlerFunc, path, body string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return resp.StatusCode, result
}

// TestHandlePairInit_Success 验证 pair/init 成功返回 pair_token 和 check_token
func TestHandlePairInit_Success(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	status, body := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-001","device_name":"MacBook Pro"}`)

	if status != http.StatusOK {
		t.Errorf("期望 200，实际 %d", status)
	}
	pairToken, _ := body["pair_token"].(string)
	if pairToken == "" {
		t.Error("pair_token 不应为空")
	}
	checkToken, _ := body["check_token"].(string)
	if checkToken == "" {
		t.Error("check_token 不应为空")
	}
	// 验证 token 格式（64 字节 hex = 32 字节随机数）
	if len(pairToken) != 64 {
		t.Errorf("pair_token 长度应为 64，实际 %d", len(pairToken))
	}
	if len(checkToken) != 64 {
		t.Errorf("check_token 长度应为 64，实际 %d", len(checkToken))
	}
}

// TestHandlePairInit_MissingFields 验证缺少必填字段时返回 400
func TestHandlePairInit_MissingFields(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	// 缺少 device_name
	status, _ := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-001"}`)
	if status != http.StatusBadRequest {
		t.Errorf("缺少 device_name 期望 400，实际 %d", status)
	}

	// 缺少 device_id
	status, _ = testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_name":"MacBook"}`)
	if status != http.StatusBadRequest {
		t.Errorf("缺少 device_id 期望 400，实际 %d", status)
	}

	// 空 body
	status, _ = testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init", `{}`)
	if status != http.StatusBadRequest {
		t.Errorf("空 body 期望 400，实际 %d", status)
	}
}

// TestHandlePairInit_InvalidJSON 验证非法 JSON 返回 400
func TestHandlePairInit_InvalidJSON(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	status, _ := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init", `not-json`)
	if status != http.StatusBadRequest {
		t.Errorf("非法 JSON 期望 400，实际 %d", status)
	}
}

// TestHandlePairConfirm_Success 验证完整的 init→confirm 配对流程
func TestHandlePairConfirm_Success(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	// 1. 先调用 init，获取 pair_token
	_, initBody := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-002","device_name":"Mac Mini"}`)
	pairToken, _ := initBody["pair_token"].(string)
	if pairToken == "" {
		t.Fatal("init 未返回 pair_token")
	}

	// 2. 调用 confirm，完成配对
	confirmBody := fmt.Sprintf(`{"pair_token":"%s","phone_id":"phone-002","phone_name":"iPhone 15"}`, pairToken)
	status, body := testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm", confirmBody)

	if status != http.StatusOK {
		t.Errorf("期望 200，实际 %d，body: %v", status, body)
	}
	deviceID, _ := body["device_id"].(string)
	if deviceID != "mac-002" {
		t.Errorf("期望 device_id=mac-002，实际 %s", deviceID)
	}
	deviceName, _ := body["device_name"].(string)
	if deviceName != "Mac Mini" {
		t.Errorf("期望 device_name=Mac Mini，实际 %s", deviceName)
	}
	pairSecret, _ := body["pair_secret"].(string)
	if len(pairSecret) != 64 {
		t.Errorf("pair_secret 长度应为 64，实际 %d", len(pairSecret))
	}
}

// TestHandlePairConfirm_InvalidToken 验证无效 pair_token 返回 401
func TestHandlePairConfirm_InvalidToken(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	status, body := testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm",
		`{"pair_token":"invalid-token","phone_id":"phone-x","phone_name":"iPhone"}`)
	if status != http.StatusUnauthorized {
		t.Errorf("无效 token 期望 401，实际 %d，body: %v", status, body)
	}
}

// TestHandlePairConfirm_TokenConsumedOnce 验证同一 pair_token 只能消费一次
func TestHandlePairConfirm_TokenConsumedOnce(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	_, initBody := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-003","device_name":"Mac Pro"}`)
	pairToken, _ := initBody["pair_token"].(string)

	confirmBody := fmt.Sprintf(`{"pair_token":"%s","phone_id":"phone-003","phone_name":"iPhone"}`, pairToken)

	// 第一次调用应成功
	status, _ := testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm", confirmBody)
	if status != http.StatusOK {
		t.Errorf("第一次 confirm 期望 200，实际 %d", status)
	}

	// 第二次调用同一 token 应返回 401（token 已消费）
	status, _ = testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm", confirmBody)
	if status != http.StatusUnauthorized {
		t.Errorf("重复 confirm 期望 401，实际 %d", status)
	}
}

// TestHandlePairConfirm_MissingFields 验证缺少必填字段时返回 400
func TestHandlePairConfirm_MissingFields(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	// 缺少 phone_id
	status, _ := testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm",
		`{"pair_token":"tok","phone_name":"iPhone"}`)
	if status != http.StatusBadRequest {
		t.Errorf("缺少 phone_id 期望 400，实际 %d", status)
	}

	// 缺少 pair_token
	status, _ = testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm",
		`{"phone_id":"p1","phone_name":"iPhone"}`)
	if status != http.StatusBadRequest {
		t.Errorf("缺少 pair_token 期望 400，实际 %d", status)
	}
}

// TestHandlePairCheck_Success 验证 init→confirm→check 完整轮询流程
func TestHandlePairCheck_Success(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	// init
	_, initBody := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-check-1","device_name":"Test Mac"}`)
	pairToken, _ := initBody["pair_token"].(string)
	checkToken, _ := initBody["check_token"].(string)

	// confirm
	confirmBody := fmt.Sprintf(`{"pair_token":"%s","phone_id":"phone-check-1","phone_name":"Test iPhone"}`, pairToken)
	testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm", confirmBody)

	// check（Mac 轮询获取 pair_secret）
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/pair/check/mac-check-1?check_token=%s", checkToken), nil)
	w := httptest.NewRecorder()
	ph.HandlePairCheck(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("期望 200，实际 %d", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "paired" {
		t.Errorf("期望 status=paired，实际 %s", body["status"])
	}
	if body["phone_id"] != "phone-check-1" {
		t.Errorf("期望 phone_id=phone-check-1，实际 %s", body["phone_id"])
	}
	if len(body["pair_secret"]) != 64 {
		t.Errorf("pair_secret 长度应为 64，实际 %d", len(body["pair_secret"]))
	}
}

// TestHandlePairCheck_NotPaired 验证未配对时返回 404
func TestHandlePairCheck_NotPaired(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	req := httptest.NewRequest(http.MethodGet,
		"/api/pair/check/nonexistent?check_token=sometoken", nil)
	w := httptest.NewRecorder()
	ph.HandlePairCheck(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("期望 404，实际 %d", w.Code)
	}
}

// TestHandlePairCheck_MissingCheckToken 验证缺少 check_token 时返回 401
func TestHandlePairCheck_MissingCheckToken(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/pair/check/mac-001", nil)
	w := httptest.NewRecorder()
	ph.HandlePairCheck(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("期望 401，实际 %d", w.Code)
	}
}

// TestHandlePairCheck_WrongCheckToken 验证错误的 check_token 返回 404（不泄露信息）
func TestHandlePairCheck_WrongCheckToken(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	// init + confirm
	_, initBody := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-check-2","device_name":"Test Mac"}`)
	pairToken, _ := initBody["pair_token"].(string)
	testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm",
		fmt.Sprintf(`{"pair_token":"%s","phone_id":"phone-check-2","phone_name":"iPhone"}`, pairToken))

	// 使用错误的 check_token 轮询
	req := httptest.NewRequest(http.MethodGet,
		"/api/pair/check/mac-check-2?check_token=wrong-token", nil)
	w := httptest.NewRecorder()
	ph.HandlePairCheck(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("期望 404，实际 %d", w.Code)
	}
}

// TestHandlePairCheck_SecretConsumedOnce 验证 pair_secret 只能通过 check 接口取回一次
func TestHandlePairCheck_SecretConsumedOnce(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	_, initBody := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-check-3","device_name":"Mac"}`)
	pairToken, _ := initBody["pair_token"].(string)
	checkToken, _ := initBody["check_token"].(string)

	testPairHandlerPost(t, ph.HandlePairConfirm, "/api/pair/confirm",
		fmt.Sprintf(`{"pair_token":"%s","phone_id":"phone-check-3","phone_name":"iPhone"}`, pairToken))

	// 第一次 check 成功
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/pair/check/mac-check-3?check_token=%s", checkToken), nil)
	w := httptest.NewRecorder()
	ph.HandlePairCheck(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("第一次 check 期望 200，实际 %d", w.Code)
	}

	// 第二次 check 应返回 404（secret 已消费）
	req2 := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/pair/check/mac-check-3?check_token=%s", checkToken), nil)
	w2 := httptest.NewRecorder()
	ph.HandlePairCheck(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("第二次 check 期望 404（已消费），实际 %d", w2.Code)
	}
}

// TestHandlePairDelete_Success 验证 DELETE /api/pair/{phone_id} 成功解除配对
func TestHandlePairDelete_Success(t *testing.T) {
	srv, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("创建 server 失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := "mac-del-1"
	phoneID := "phone-del-1"

	// 完成配对
	pairSecret := testPairDeviceAndPhone(t, ts.URL, deviceID, phoneID)

	// 计算签名
	secretHash := testSHA256Hex(pairSecret)
	nowTS := time.Now().Unix()
	path := "/api/pair/" + phoneID
	mac := hmac.New(sha256.New, []byte(secretHash))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d", phoneID, path, nowTS)))
	sig := hex.EncodeToString(mac.Sum(nil))

	// 发送 DELETE 请求
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+path, nil)
	req.Header.Set("X-Phone-ID", phoneID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", nowTS))
	req.Header.Set("X-Signature", sig)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("期望 204，实际 %d", resp.StatusCode)
	}
}

// TestHandlePairDelete_MissingAuth 验证缺少认证头时返回 401
func TestHandlePairDelete_MissingAuth(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/pair/phone-x", nil)
	w := httptest.NewRecorder()
	ph.HandlePairDelete(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("缺少认证头期望 401，实际 %d", w.Code)
	}
}

// TestHandlePairDelete_PhoneIDMismatch 验证 header phone_id 与 URL phone_id 不一致时返回 403
func TestHandlePairDelete_PhoneIDMismatch(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/pair/phone-real", nil)
	req.Header.Set("X-Phone-ID", "phone-fake")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-Signature", "doesnt-matter")
	w := httptest.NewRecorder()
	ph.HandlePairDelete(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("phone_id 不一致期望 403，实际 %d", w.Code)
	}
}

// TestHandlePairDelete_NotFound 验证删除不存在的配对返回 404
func TestHandlePairDelete_NotFound(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/pair/nonexistent", nil)
	req.Header.Set("X-Phone-ID", "nonexistent")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-Signature", "sig")
	w := httptest.NewRecorder()
	ph.HandlePairDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("不存在配对期望 404，实际 %d", w.Code)
	}
}

// TestHandlePairInit_TokenUniqueness 验证每次 init 返回不同的 pair_token
func TestHandlePairInit_TokenUniqueness(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	_, body1 := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-uniq","device_name":"Mac"}`)
	_, body2 := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-uniq","device_name":"Mac"}`)

	token1, _ := body1["pair_token"].(string)
	token2, _ := body2["pair_token"].(string)

	if token1 == "" || token2 == "" {
		t.Fatal("两次 init 均应返回非空 token")
	}
	if token1 == token2 {
		t.Error("两次 init 应返回不同的 pair_token")
	}
}

// TestPairTokenFormat 验证 pair_token 是合法的十六进制字符串
func TestPairTokenFormat(t *testing.T) {
	ph, _ := newTestPairHandler(t)

	_, body := testPairHandlerPost(t, ph.HandlePairInit, "/api/pair/init",
		`{"device_id":"mac-fmt","device_name":"Mac"}`)
	token, _ := body["pair_token"].(string)

	// 验证只包含十六进制字符
	if !isHexString(token) {
		t.Errorf("pair_token 应为合法十六进制字符串，实际: %s", token)
	}
}

// isHexString 检查字符串是否全部由十六进制字符组成
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))
	}) == -1
}
