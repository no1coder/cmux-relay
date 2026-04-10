package store_test

import (
	"testing"
	"time"

	"github.com/manaflow-ai/cmux-relay/store"
)

// newTestStore 创建一个内存 SQLite store 用于测试
func newTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("创建测试 store 失败: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestPairAndLookup 测试保存配对后通过 device 和 phone 查询
func TestPairAndLookup(t *testing.T) {
	s := newTestStore(t)

	pair := store.Pair{
		DeviceID:   "device-001",
		DeviceName: "MacBook Pro",
		PhoneID:    "phone-001",
		PhoneName:  "iPhone 15",
		SecretHash: "sha256hashvalue",
		APNsToken:  "apns-token-abc",
	}

	if err := s.SavePair(pair); err != nil {
		t.Fatalf("SavePair 失败: %v", err)
	}

	// 通过 device 查询
	got, err := s.LookupPairByDevice("device-001")
	if err != nil {
		t.Fatalf("LookupPairByDevice 失败: %v", err)
	}
	if got.PhoneID != "phone-001" {
		t.Errorf("期望 PhoneID=phone-001, 得到 %s", got.PhoneID)
	}
	if got.DeviceName != "MacBook Pro" {
		t.Errorf("期望 DeviceName=MacBook Pro, 得到 %s", got.DeviceName)
	}

	// 通过 phone 查询
	got2, err := s.LookupPairByPhone("phone-001")
	if err != nil {
		t.Fatalf("LookupPairByPhone 失败: %v", err)
	}
	if got2.DeviceID != "device-001" {
		t.Errorf("期望 DeviceID=device-001, 得到 %s", got2.DeviceID)
	}
	if got2.APNsToken != "apns-token-abc" {
		t.Errorf("期望 APNsToken=apns-token-abc, 得到 %s", got2.APNsToken)
	}
}

// TestDeletePair 测试删除配对后查询返回 ErrPairNotFound
func TestDeletePair(t *testing.T) {
	s := newTestStore(t)

	pair := store.Pair{
		DeviceID:   "device-002",
		DeviceName: "iMac",
		PhoneID:    "phone-002",
		PhoneName:  "iPhone 14",
		SecretHash: "somehash",
		APNsToken:  "token-xyz",
	}

	if err := s.SavePair(pair); err != nil {
		t.Fatalf("SavePair 失败: %v", err)
	}

	if err := s.DeletePair("device-002"); err != nil {
		t.Fatalf("DeletePair 失败: %v", err)
	}

	// 删除后查询应返回 ErrPairNotFound
	_, err := s.LookupPairByDevice("device-002")
	if err != store.ErrPairNotFound {
		t.Errorf("期望 ErrPairNotFound, 得到 %v", err)
	}
}

// TestPairTokenLifecycle 测试创建 token、消费 token、再次消费应失败
func TestPairTokenLifecycle(t *testing.T) {
	s := newTestStore(t)

	// 创建 token（带 device_name），同时返回 check_token
	token, checkToken, err := s.CreatePairToken("device-003", "MacBook Pro Test")
	if err != nil {
		t.Fatalf("CreatePairToken 失败: %v", err)
	}
	if len(token) == 0 {
		t.Fatal("token 不应为空")
	}
	if len(checkToken) == 0 {
		t.Fatal("check_token 不应为空")
	}

	// 第一次消费 token 应成功，且返回 deviceName 和 checkToken
	deviceID, deviceName, gotCheckToken, err := s.ConsumePairToken(token)
	if err != nil {
		t.Fatalf("ConsumePairToken 第一次调用失败: %v", err)
	}
	if deviceID != "device-003" {
		t.Errorf("期望 deviceID=device-003, 得到 %s", deviceID)
	}
	if deviceName != "MacBook Pro Test" {
		t.Errorf("期望 deviceName=MacBook Pro Test, 得到 %s", deviceName)
	}
	if gotCheckToken != checkToken {
		t.Errorf("期望 checkToken=%s, 得到 %s", checkToken, gotCheckToken)
	}

	// 第二次消费同一 token 应失败
	_, _, _, err = s.ConsumePairToken(token)
	if err != store.ErrTokenInvalid {
		t.Errorf("期望 ErrTokenInvalid, 得到 %v", err)
	}
}

// TestUpdateLiveActivityToken 测试更新 Live Activity token 后可查询到新值
func TestUpdateLiveActivityToken(t *testing.T) {
	s := newTestStore(t)

	// 先创建配对记录
	err := s.SavePair(store.Pair{
		DeviceID: "mac1", DeviceName: "Mac", PhoneID: "phone1", PhoneName: "iPhone",
		SecretHash: "hash", APNsToken: "apns-token-1", CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 更新 LA token
	err = s.UpdateLiveActivityToken("phone1", "la-token-123")
	if err != nil {
		t.Fatal(err)
	}

	// 验证查询到新值
	token, err := s.LookupLiveActivityToken("phone1")
	if err != nil {
		t.Fatal(err)
	}
	if token != "la-token-123" {
		t.Errorf("期望 la-token-123，实际 %s", token)
	}
}

// TestUpdateLiveActivityToken_NotFound 测试更新不存在的 phone 返回 ErrPairNotFound
func TestUpdateLiveActivityToken_NotFound(t *testing.T) {
	s := newTestStore(t)

	err := s.UpdateLiveActivityToken("nonexistent", "token")
	if err != store.ErrPairNotFound {
		t.Errorf("期望 ErrPairNotFound，实际 %v", err)
	}
}

// TestLookupLiveActivityToken_Empty 测试未设置 LA token 时返回空字符串
func TestLookupLiveActivityToken_Empty(t *testing.T) {
	s := newTestStore(t)

	// 创建配对但不设置 LA token
	_ = s.SavePair(store.Pair{
		DeviceID: "mac1", DeviceName: "Mac", PhoneID: "phone1", PhoneName: "iPhone",
		SecretHash: "hash", APNsToken: "apns", CreatedAt: time.Now(),
	})

	token, err := s.LookupLiveActivityToken("phone1")
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		t.Errorf("期望空字符串，实际 %s", token)
	}
}

// TestLookupLiveActivityToken_NotFound 测试查询不存在 phone 的 LA token 返回 ErrPairNotFound
func TestLookupLiveActivityToken_NotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.LookupLiveActivityToken("nonexistent-phone")
	if err != store.ErrPairNotFound {
		t.Errorf("期望 ErrPairNotFound，实际 %v", err)
	}
}

// TestUpdateLiveActivityToken_Overwrite 测试多次更新 LA token 只保留最新值
func TestUpdateLiveActivityToken_Overwrite(t *testing.T) {
	s := newTestStore(t)

	_ = s.SavePair(store.Pair{
		DeviceID: "mac1", DeviceName: "Mac", PhoneID: "phone1", PhoneName: "iPhone",
		SecretHash: "hash", APNsToken: "apns", CreatedAt: time.Now(),
	})

	// 第一次更新
	_ = s.UpdateLiveActivityToken("phone1", "token-v1")
	// 第二次更新（覆盖）
	_ = s.UpdateLiveActivityToken("phone1", "token-v2")

	token, err := s.LookupLiveActivityToken("phone1")
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-v2" {
		t.Errorf("期望 token-v2，实际 %s", token)
	}
}

// TestLiveActivityToken_ReflectedInLookupPairByPhone 测试通过 LookupPairByPhone 也能读取 LA token
func TestLiveActivityToken_ReflectedInLookupPairByPhone(t *testing.T) {
	s := newTestStore(t)

	_ = s.SavePair(store.Pair{
		DeviceID: "mac1", DeviceName: "Mac", PhoneID: "phone1", PhoneName: "iPhone",
		SecretHash: "hash", APNsToken: "apns", CreatedAt: time.Now(),
	})
	_ = s.UpdateLiveActivityToken("phone1", "la-abc")

	pair, err := s.LookupPairByPhone("phone1")
	if err != nil {
		t.Fatal(err)
	}
	if pair.LiveActivityToken != "la-abc" {
		t.Errorf("期望 LiveActivityToken=la-abc，实际 %s", pair.LiveActivityToken)
	}
}

// TestTryMarkNonce 测试原子化 nonce 标记：首次返回 true，重复调用返回 false
func TestTryMarkNonce(t *testing.T) {
	s := newTestStore(t)

	nonce := "atomic-nonce-xyz"
	expiresAt := time.Now().Add(60 * time.Second).Unix()

	// 首次调用应返回 firstUse=true
	firstUse, err := s.TryMarkNonce(nonce, expiresAt)
	if err != nil {
		t.Fatalf("TryMarkNonce 首次调用失败: %v", err)
	}
	if !firstUse {
		t.Error("TryMarkNonce 首次调用应返回 firstUse=true")
	}

	// 重复调用同一 nonce 应返回 firstUse=false（防重放）
	firstUse, err = s.TryMarkNonce(nonce, expiresAt)
	if err != nil {
		t.Fatalf("TryMarkNonce 第二次调用失败: %v", err)
	}
	if firstUse {
		t.Error("TryMarkNonce 重复调用应返回 firstUse=false")
	}
}
