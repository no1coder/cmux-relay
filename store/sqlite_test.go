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

	// 创建 token
	token, err := s.CreatePairToken("device-003")
	if err != nil {
		t.Fatalf("CreatePairToken 失败: %v", err)
	}
	if len(token) == 0 {
		t.Fatal("token 不应为空")
	}

	// 第一次消费 token 应成功
	deviceID, err := s.ConsumePairToken(token)
	if err != nil {
		t.Fatalf("ConsumePairToken 第一次调用失败: %v", err)
	}
	if deviceID != "device-003" {
		t.Errorf("期望 deviceID=device-003, 得到 %s", deviceID)
	}

	// 第二次消费同一 token 应失败
	_, err = s.ConsumePairToken(token)
	if err != store.ErrTokenInvalid {
		t.Errorf("期望 ErrTokenInvalid, 得到 %v", err)
	}
}

// TestNonceDedup 测试 nonce 去重：首次检查未使用，标记使用，再次检查已使用
func TestNonceDedup(t *testing.T) {
	s := newTestStore(t)

	nonce := "test-nonce-12345"

	// 首次检查：未使用
	used, err := s.IsNonceUsed(nonce)
	if err != nil {
		t.Fatalf("IsNonceUsed 失败: %v", err)
	}
	if used {
		t.Error("nonce 应尚未使用")
	}

	// 标记为已使用
	if err := s.MarkNonceUsed(nonce, time.Now()); err != nil {
		t.Fatalf("MarkNonceUsed 失败: %v", err)
	}

	// 再次检查：已使用
	used, err = s.IsNonceUsed(nonce)
	if err != nil {
		t.Fatalf("IsNonceUsed 第二次调用失败: %v", err)
	}
	if !used {
		t.Error("nonce 应已标记为使用")
	}
}
