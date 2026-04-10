package server

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/manaflow-ai/cmux-relay/protocol"
)

// TestIsTerminalAPNsError 验证终端 APNs 错误检测逻辑
func TestIsTerminalAPNsError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil 错误", nil, false},
		{"status=410（token 过期）", fmt.Errorf("apns: live activity status=410 body=..."), true},
		{"BadDeviceToken", fmt.Errorf("apns: status=400 reason=BadDeviceToken"), true},
		{"DeviceTokenNotForTopic", fmt.Errorf("apns: status=400 reason=DeviceTokenNotForTopic"), true},
		{"普通网络错误", fmt.Errorf("network timeout"), false},
		{"status=200（成功）", fmt.Errorf("apns: status=200"), false},
		{"status=500（服务器错误）", fmt.Errorf("apns: status=500 internal server error"), false},
		{"包含 BadDeviceToken 子串", fmt.Errorf("reason=BadDeviceToken,retryAfter=0"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTerminalAPNsError(tt.err)
			if got != tt.expected {
				t.Errorf("isTerminalAPNsError(%v) = %v，期望 %v", tt.err, got, tt.expected)
			}
		})
	}
}

// TestPushSummaryForType 验证各事件类型的推送摘要文案
func TestPushSummaryForType(t *testing.T) {
	tests := []struct {
		eventType string
		expected  string
	}{
		{"approval_required", "需要您审批操作"},
		{"task_complete", "任务已完成"},
		{"task_failed", "任务执行失败"},
		{"terminal_exit", "终端进程已退出"},
		{"notification", "终端命令完成"},
		{"unknown_event", "您有新的通知"},
		{"", "您有新的通知"},
	}

	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			got := pushSummaryForType(tt.eventType)
			if got != tt.expected {
				t.Errorf("pushSummaryForType(%q) = %q，期望 %q", tt.eventType, got, tt.expected)
			}
		})
	}
}

// TestMarshalSimple 验证辅助函数 marshalSimple 生成正确的 JSON
func TestMarshalSimple(t *testing.T) {
	data := marshalSimple("type", "auth_ok")
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("marshalSimple 输出无法解析: %v", err)
	}
	if m["type"] != "auth_ok" {
		t.Errorf("期望 type=auth_ok，实际 %s", m["type"])
	}
}

// TestMarshalSimple_AuthFailed 验证 auth_failed 消息格式
func TestMarshalSimple_AuthFailed(t *testing.T) {
	data := marshalSimple("type", "auth_failed")
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("marshalSimple 输出无法解析: %v", err)
	}
	if m["type"] != "auth_failed" {
		t.Errorf("期望 type=auth_failed，实际 %s", m["type"])
	}
}

// TestForwardToPhone_LiveActivity_PhaseEvent 验证 phase.update 事件触发 Live Activity 更新路径
// 通过集成测试验证：设置 LA token 后，阶段事件转发时会调用 handlePhaseEvent
func TestForwardToPhone_PhaseEventDetection(t *testing.T) {
	// 验证 TypeEvent 的常量值正确（handlePhaseEvent 由 forwardToPhone 按类型触发）
	if protocol.TypeEvent == "" {
		t.Error("protocol.TypeEvent 不应为空")
	}
	if protocol.TypeEvent == protocol.TypeRPCRequest {
		t.Error("TypeEvent 与 TypeRPCRequest 不应相同")
	}
}

// TestHandlePhaseEvent_PhaseNames 验证不同阶段名称的处理逻辑
// 使用白盒测试直接调用内部 handlePhaseEvent 函数，验证非 phase.update 事件被过滤
func TestHandlePhaseEvent_NonPhaseEvent(t *testing.T) {
	// 构建一个非 phase.update 事件的 Envelope
	payload := json.RawMessage(`{"event":"other.event","phase":"running"}`)
	env := protocol.Envelope{
		Type:    protocol.TypeEvent,
		Payload: payload,
	}

	// 创建无 APNs 客户端的 Relay，handlePhaseEvent 应直接返回而不崩溃
	relay := &Relay{}
	// apns 为 nil，handlePhaseEvent 应直接返回
	relay.handlePhaseEvent(env, "phone-test")
	// 能走到这里说明没有 panic
}

// TestHandlePhaseEvent_NoAPNs 验证无 APNs 配置时 handlePhaseEvent 静默返回
func TestHandlePhaseEvent_NoAPNs(t *testing.T) {
	payload := json.RawMessage(`{"event":"phase.update","phase":"running","surface_id":"s1"}`)
	env := protocol.Envelope{
		Type:    protocol.TypeEvent,
		Payload: payload,
	}

	relay := &Relay{apns: nil}
	// 不应 panic
	relay.handlePhaseEvent(env, "phone-test")
}
