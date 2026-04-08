// Package server 提供 cmux-relay 的 WebSocket 服务器核心组件。
package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// 哨兵错误定义
var (
	// ErrTimestampDrift 表示请求时间戳超出允许的最大漂移范围
	ErrTimestampDrift = errors.New("auth: timestamp drift too large")
	// ErrInvalidSignature 表示 HMAC 签名验证失败
	ErrInvalidSignature = errors.New("auth: invalid signature")
)

// Authenticator 负责验证 HMAC-SHA256 签名和时间戳
type Authenticator struct {
	// maxTimeDrift 允许的最大时间漂移（双向）
	maxTimeDrift time.Duration
	// nonce 去重缓存：防止重放攻击
	usedNonces map[string]time.Time
}

// NewAuthenticator 创建新的 Authenticator，maxDrift 指定允许的最大时间漂移
func NewAuthenticator(maxDrift time.Duration) *Authenticator {
	a := &Authenticator{
		maxTimeDrift: maxDrift,
		usedNonces:   make(map[string]time.Time),
	}
	// 后台清理过期 nonce（每分钟清理一次）
	go a.cleanupLoop()
	return a
}

// Verify 验证请求的合法性：
//   - 检查时间戳漂移（使用 Abs 支持双向）
//   - 计算 HMAC-SHA256(secretHash, deviceID+nonce+timestamp) 并与 signature 比较
//
// 注意：客户端和服务端均使用 SHA256(pair_secret) 作为 HMAC key（即 secretHash）
func (a *Authenticator) Verify(deviceID, nonce string, ts int64, signature, secretHash string) error {
	// 检查时间戳漂移
	drift := time.Duration(abs(time.Now().Unix()-ts)) * time.Second
	if drift > a.maxTimeDrift {
		return ErrTimestampDrift
	}

	// 安全：nonce 一次性使用，防止重放攻击
	nonceKey := deviceID + ":" + nonce
	if _, used := a.usedNonces[nonceKey]; used {
		return ErrInvalidSignature
	}
	a.usedNonces[nonceKey] = time.Now()

	// 计算期望的 HMAC 签名
	expected := computeHMACHex(secretHash, deviceID, nonce, ts)

	// 使用 hmac.Equal 进行时间恒定比较，防止时序攻击
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return ErrInvalidSignature
	}
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return ErrInvalidSignature
	}

	if !hmac.Equal(expectedBytes, sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// GenerateNonce 生成 16 随机字节的 hex 编码 nonce
func GenerateNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// sha256Hash 计算字符串的 SHA256 哈希（十六进制）
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// computeHMACHex 使用 secretHash 作为 key 计算 HMAC-SHA256
// 消息格式为 deviceID:nonce:timestamp（用冒号分隔，防止字段拼接歧义）
func computeHMACHex(secretHash, deviceID, nonce string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secretHash))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d", deviceID, nonce, ts)))
	return hex.EncodeToString(mac.Sum(nil))
}

// cleanupLoop 定期清理过期 nonce
func (a *Authenticator) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-a.maxTimeDrift * 2)
		for k, t := range a.usedNonces {
			if t.Before(cutoff) {
				delete(a.usedNonces, k)
			}
		}
	}
}

// abs 返回 int64 的绝对值
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
