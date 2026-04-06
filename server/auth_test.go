package server_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/manaflow-ai/cmux-relay/server"
)

// sha256Hash 计算字符串的 SHA256 哈希（十六进制）
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// computeHMAC 使用 HMAC-SHA256 计算签名
// key 为 secretHash（即 SHA256(pair_secret)），消息为 deviceID+nonce+timestamp
func computeHMAC(secretHash, deviceID, nonce string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secretHash))
	mac.Write([]byte(fmt.Sprintf("%s%s%d", deviceID, nonce, ts)))
	return hex.EncodeToString(mac.Sum(nil))
}

// TestVerifyAuth_Valid 测试合法签名通过验证
func TestVerifyAuth_Valid(t *testing.T) {
	auth := server.NewAuthenticator(10 * time.Second)

	secret := "my-pair-secret"
	secretHash := sha256Hash(secret)
	deviceID := "device-001"
	nonce := "random-nonce-abc"
	ts := time.Now().Unix()

	sig := computeHMAC(secretHash, deviceID, nonce, ts)

	if err := auth.Verify(deviceID, nonce, ts, sig, secretHash); err != nil {
		t.Errorf("合法签名验证失败: %v", err)
	}
}

// TestVerifyAuth_ExpiredTimestamp 测试时间戳过期返回 ErrTimestampDrift
func TestVerifyAuth_ExpiredTimestamp(t *testing.T) {
	// 最大漂移 10 秒
	auth := server.NewAuthenticator(10 * time.Second)

	secret := "my-pair-secret"
	secretHash := sha256Hash(secret)
	deviceID := "device-001"
	nonce := "random-nonce-abc"
	// 30 秒前的时间戳，超出 10 秒漂移
	ts := time.Now().Add(-30 * time.Second).Unix()

	sig := computeHMAC(secretHash, deviceID, nonce, ts)

	err := auth.Verify(deviceID, nonce, ts, sig, secretHash)
	if err != server.ErrTimestampDrift {
		t.Errorf("期望 ErrTimestampDrift, 得到 %v", err)
	}
}

// TestVerifyAuth_BadSignature 测试错误密钥导致签名不匹配返回 ErrInvalidSignature
func TestVerifyAuth_BadSignature(t *testing.T) {
	auth := server.NewAuthenticator(10 * time.Second)

	deviceID := "device-001"
	nonce := "random-nonce-abc"
	ts := time.Now().Unix()

	// 用错误密钥计算签名
	wrongSecretHash := sha256Hash("wrong-secret")
	sig := computeHMAC(wrongSecretHash, deviceID, nonce, ts)

	// 验证时使用正确的 secretHash
	correctSecretHash := sha256Hash("correct-secret")

	err := auth.Verify(deviceID, nonce, ts, sig, correctSecretHash)
	if err != server.ErrInvalidSignature {
		t.Errorf("期望 ErrInvalidSignature, 得到 %v", err)
	}
}
