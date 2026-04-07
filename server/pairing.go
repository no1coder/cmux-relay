package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/manaflow-ai/cmux-relay/store"
)

// PairHandler 处理配对相关的 REST API
type PairHandler struct {
	store  *store.SQLiteStore
	router *Router
}

// NewPairHandler 创建 PairHandler
func NewPairHandler(s *store.SQLiteStore, r *Router) *PairHandler {
	return &PairHandler{store: s, router: r}
}

// --- 请求 / 响应结构体 ---

type pairInitRequest struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
}

type pairInitResponse struct {
	PairToken  string `json:"pair_token"`
	CheckToken string `json:"check_token"`
}

type pairConfirmRequest struct {
	PairToken string `json:"pair_token"`
	PhoneID   string `json:"phone_id"`
	PhoneName string `json:"phone_name"`
}

type pairConfirmResponse struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	PairSecret string `json:"pair_secret"`
}

// HandlePairInit 处理 POST /api/pair/init
// iOS 扫码触发 Mac 发起配对请求，Mac 调用此接口获取一次性 pair_token
func (h *PairHandler) HandlePairInit(w http.ResponseWriter, r *http.Request) {
	var req pairInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DeviceID == "" || req.DeviceName == "" {
		writeError(w, http.StatusBadRequest, "device_id and device_name are required")
		return
	}

	token, checkToken, err := h.store.CreatePairToken(req.DeviceID, req.DeviceName)
	if err != nil {
		log.Printf("[pairing] CreatePairToken error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to create pair token")
		return
	}

	writeJSON(w, http.StatusOK, pairInitResponse{PairToken: token, CheckToken: checkToken})
}

// HandlePairConfirm 处理 POST /api/pair/confirm
// iOS 扫码后调用此接口完成配对，返回 pair_secret
func (h *PairHandler) HandlePairConfirm(w http.ResponseWriter, r *http.Request) {
	var req pairConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PairToken == "" || req.PhoneID == "" || req.PhoneName == "" {
		writeError(w, http.StatusBadRequest, "pair_token, phone_id and phone_name are required")
		return
	}

	// 消费 pair token，获取对应的 device_id、device_name 和 check_token
	deviceID, deviceName, checkToken, err := h.store.ConsumePairToken(req.PairToken)
	if err != nil {
		if errors.Is(err, store.ErrTokenInvalid) {
			writeError(w, http.StatusUnauthorized, "pair token invalid or expired")
			return
		}
		log.Printf("[pairing] ConsumePairToken error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to consume pair token")
		return
	}

	// 生成 32 字节随机 pair_secret
	rawSecret := make([]byte, 32)
	if _, err := rand.Read(rawSecret); err != nil {
		log.Printf("[pairing] rand.Read error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to generate pair secret")
		return
	}
	pairSecret := hex.EncodeToString(rawSecret)

	// 计算 SHA256(pair_secret) 存入数据库
	hash := sha256.Sum256([]byte(pairSecret))
	secretHash := hex.EncodeToString(hash[:])

	// device_name 已从 pair_token 记录中获取，无需再查询或降级处理
	pair := store.Pair{
		DeviceID:   deviceID,
		DeviceName: deviceName,
		PhoneID:    req.PhoneID,
		PhoneName:  req.PhoneName,
		SecretHash: secretHash,
		APNsToken:  "",
		CreatedAt:  time.Now(),
	}
	if err := h.store.SavePair(pair); err != nil {
		log.Printf("[pairing] SavePair error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to save pair")
		return
	}

	// 暂存 pair_secret 供 Mac 轮询取回（Mac 在配对期间可能没有 WebSocket 连接）
	// check_token 用于验证轮询方身份
	if err := h.store.SavePendingSecret(deviceID, pairSecret, checkToken); err != nil {
		log.Printf("[pairing] SavePendingSecret error: %v", err)
		// 非致命错误，继续处理
	}

	// 如果 Mac 在线，通过 WebSocket 通知配对完成
	if dc := h.router.GetDevice(deviceID); dc != nil {
		notify := map[string]string{
			"type":       "pair_confirmed",
			"phone_id":   req.PhoneID,
			"phone_name": req.PhoneName,
		}
		if data, err := json.Marshal(notify); err == nil {
			// 使用 SafeWrite 发送，忽略错误（Mac 可能已断开）
			_ = dc.SafeWrite(websocket.TextMessage, data)
		}
	}

	writeJSON(w, http.StatusOK, pairConfirmResponse{
		DeviceID:   deviceID,
		DeviceName: deviceName,
		PairSecret: pairSecret,
	})
}

// HandlePairCheck 处理 GET /api/pair/check/{device_id}?check_token=xxx
// Mac 在显示 QR 码后轮询此接口，获取 iOS 确认后暂存的 pair_secret
// 需要提供 check_token（init 时返回的）作为认证凭证，防止未授权访问
func (h *PairHandler) HandlePairCheck(w http.ResponseWriter, r *http.Request) {
	deviceID := strings.TrimPrefix(r.URL.Path, "/api/pair/check/")
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	// 验证 check_token 参数，防止未授权方轮询获取 pair_secret
	checkToken := r.URL.Query().Get("check_token")
	if checkToken == "" {
		writeError(w, http.StatusUnauthorized, "check_token is required")
		return
	}

	pairSecret, phoneName, phoneID, err := h.store.ConsumePendingSecret(deviceID, checkToken)
	if err != nil {
		// 未找到、已过期或 check_token 不匹配：尚未配对
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "not_paired"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "paired",
		"phone_id":    phoneID,
		"phone_name":  phoneName,
		"pair_secret": pairSecret,
	})
}

// HandlePairDelete 处理 DELETE /api/pair/{phone_id}
// 解除配对，关闭 Phone 连接，通知 Mac
// TODO(security): 添加 HMAC 签名认证（X-Signature + X-Timestamp），防止未授权删除配对
func (h *PairHandler) HandlePairDelete(w http.ResponseWriter, r *http.Request) {
	// 从 URL path 末尾提取 phone_id
	phoneID := strings.TrimPrefix(r.URL.Path, "/api/pair/")
	phoneID = strings.TrimSpace(phoneID)
	if phoneID == "" {
		writeError(w, http.StatusBadRequest, "phone_id is required")
		return
	}

	pair, err := h.store.LookupPairByPhone(phoneID)
	if err != nil {
		if errors.Is(err, store.ErrPairNotFound) {
			writeError(w, http.StatusNotFound, "pair not found")
			return
		}
		log.Printf("[pairing] LookupPairByPhone error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to lookup pair")
		return
	}

	if err := h.store.DeletePair(pair.DeviceID); err != nil {
		log.Printf("[pairing] DeletePair error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to delete pair")
		return
	}

	// 关闭 Phone 的 WebSocket 连接
	if pc := h.router.GetPhone(phoneID); pc != nil {
		_ = pc.Conn.Close()
		h.router.UnregisterPhone(phoneID)
	}

	// 通知 Mac 配对已解除
	if dc := h.router.GetDevice(pair.DeviceID); dc != nil {
		notify := map[string]string{
			"type":     "pair_deleted",
			"phone_id": phoneID,
		}
		if data, err := json.Marshal(notify); err == nil {
			_ = dc.SafeWrite(websocket.TextMessage, data)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- 辅助函数 ---

// writeJSON 序列化 v 为 JSON 并写入响应
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[http] writeJSON encode error: %v", err)
	}
}

// writeError 写入标准错误响应
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
