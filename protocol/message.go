// Package protocol 定义了 cmux-relay 中所有消息的数据结构和校验逻辑。
package protocol

import (
	"encoding/json"
	"errors"
)

// Origin 表示消息的来源端
type Origin string

const (
	// OriginMac 表示消息来自 Mac 桌面端
	OriginMac Origin = "mac"
	// OriginPhone 表示消息来自 iOS 手机端
	OriginPhone Origin = "phone"
)

// MessageType 表示消息的业务类型
type MessageType string

const (
	// TypeRPCRequest 表示 RPC 调用请求
	TypeRPCRequest MessageType = "rpc_request"
	// TypeRPCResponse 表示 RPC 调用响应
	TypeRPCResponse MessageType = "rpc_response"
	// TypeEvent 表示事件通知
	TypeEvent MessageType = "event"
	// TypeScreenSnapshot 表示屏幕快照
	TypeScreenSnapshot MessageType = "screen_snapshot"
	// TypeResume 表示会话恢复
	TypeResume MessageType = "resume"
	// TypeAuth 表示认证握手
	TypeAuth MessageType = "auth"
)

// PushHint 是明文推送提示，用于 E2E 加密消息的 APNs 路由。
// 当 payload 被端到端加密时，relay 无法解析 payload 内容，
// 因此发送端在信封外层附带 push_hint 供 relay 决定是否推送以及推送内容。
type PushHint struct {
	// Event 是事件类型，用于匹配推送规则
	Event string `json:"event"`
	// Summary 是推送摘要文本
	Summary string `json:"summary"`
}

// Envelope 是 cmux-relay 中所有消息的通用信封结构，包裹业务 Payload。
type Envelope struct {
	// Seq 是消息的单调递增序列号，用于排序和去重
	Seq uint64 `json:"seq"`
	// Ts 是消息的 Unix 时间戳（毫秒）
	Ts int64 `json:"ts"`
	// From 表示消息的来源端
	From Origin `json:"from"`
	// Type 表示消息的业务类型
	Type MessageType `json:"type"`
	// PushHintData 是明文推送提示，仅在 E2E 加密消息中使用
	PushHintData *PushHint `json:"push_hint,omitempty"`
	// Payload 是消息的业务数据，使用原始 JSON 延迟解析
	Payload json.RawMessage `json:"payload"`
}

// IsE2E 检查 payload 是否为端到端加密格式（包含 "e2e": true）
func (e Envelope) IsE2E() bool {
	if len(e.Payload) == 0 {
		return false
	}
	var probe struct {
		E2E bool `json:"e2e"`
	}
	if err := json.Unmarshal(e.Payload, &probe); err != nil {
		return false
	}
	return probe.E2E
}

// Validate 校验 Envelope 的必填字段，任意字段缺失时返回错误。
func (e Envelope) Validate() error {
	if e.From == "" {
		return errors.New("envelope: From 字段不能为空")
	}
	if e.Type == "" {
		return errors.New("envelope: Type 字段不能为空")
	}
	if len(e.Payload) == 0 {
		return errors.New("envelope: Payload 字段不能为空")
	}
	return nil
}
