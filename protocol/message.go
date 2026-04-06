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
	// Payload 是消息的业务数据，使用原始 JSON 延迟解析
	Payload json.RawMessage `json:"payload"`
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
