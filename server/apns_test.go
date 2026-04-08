package server

import (
	"testing"
)

// TestBuildAPNsPayload_ApprovalRequired 验证 approval_required 事件的 payload
func TestBuildAPNsPayload_ApprovalRequired(t *testing.T) {
	payload := buildAPNsPayload("approval_required", "需要审批操作")

	aps, ok := payload["aps"].(map[string]interface{})
	if !ok {
		t.Fatal("payload 缺少 aps 字段")
	}

	alert, ok := aps["alert"].(map[string]interface{})
	if !ok {
		t.Fatal("aps 缺少 alert 字段")
	}

	if alert["title"] != "权限审批" {
		t.Errorf("期望 title='权限审批'，实际='%v'", alert["title"])
	}
	if alert["body"] != "需要审批操作" {
		t.Errorf("期望 body='需要审批操作'，实际='%v'", alert["body"])
	}
	if aps["sound"] != "default" {
		t.Errorf("期望 sound='default'，实际='%v'", aps["sound"])
	}
	if aps["category"] != "APPROVAL_REQUEST" {
		t.Errorf("期望 category='APPROVAL_REQUEST'，实际='%v'", aps["category"])
	}
	if payload["event_type"] != "approval_required" {
		t.Errorf("期望 event_type='approval_required'，实际='%v'", payload["event_type"])
	}
}

// TestBuildAPNsPayload_TaskComplete 验证 task_complete 事件的 payload
func TestBuildAPNsPayload_TaskComplete(t *testing.T) {
	payload := buildAPNsPayload("task_complete", "任务已完成")

	aps := payload["aps"].(map[string]interface{})
	alert := aps["alert"].(map[string]interface{})

	if alert["title"] != "任务完成" {
		t.Errorf("期望 title='任务完成'，实际='%v'", alert["title"])
	}
	if aps["category"] != "TASK_COMPLETE" {
		t.Errorf("期望 category='TASK_COMPLETE'，实际='%v'", aps["category"])
	}
	if aps["sound"] != "default" {
		t.Errorf("期望 sound='default'，实际='%v'", aps["sound"])
	}
}

// TestBuildAPNsPayload_TaskFailed 验证 task_failed 事件的 payload
func TestBuildAPNsPayload_TaskFailed(t *testing.T) {
	payload := buildAPNsPayload("task_failed", "任务执行失败")

	aps := payload["aps"].(map[string]interface{})
	alert := aps["alert"].(map[string]interface{})

	if alert["title"] != "任务失败" {
		t.Errorf("期望 title='任务失败'，实际='%v'", alert["title"])
	}
	if aps["category"] != "TASK_FAILED" {
		t.Errorf("期望 category='TASK_FAILED'，实际='%v'", aps["category"])
	}
	if aps["sound"] != "default" {
		t.Errorf("期望 sound='default'，实际='%v'", aps["sound"])
	}
}

// TestBuildAPNsPayload_TerminalExit 验证 terminal_exit 事件的 payload
func TestBuildAPNsPayload_TerminalExit(t *testing.T) {
	payload := buildAPNsPayload("terminal_exit", "终端已退出")

	aps := payload["aps"].(map[string]interface{})
	alert := aps["alert"].(map[string]interface{})

	if alert["title"] != "终端退出" {
		t.Errorf("期望 title='终端退出'，实际='%v'", alert["title"])
	}
	if aps["category"] != "TERMINAL_EXIT" {
		t.Errorf("期望 category='TERMINAL_EXIT'，实际='%v'", aps["category"])
	}
	if aps["sound"] != "default" {
		t.Errorf("期望 sound='default'，实际='%v'", aps["sound"])
	}
}

// TestBuildAPNsPayload_UnknownEvent 验证未知事件类型使用默认值
func TestBuildAPNsPayload_UnknownEvent(t *testing.T) {
	payload := buildAPNsPayload("unknown_event", "未知事件")

	aps := payload["aps"].(map[string]interface{})
	alert := aps["alert"].(map[string]interface{})

	if alert["title"] == "" {
		t.Error("未知事件类型应有默认 title")
	}
	if aps["category"] == "" {
		t.Error("未知事件类型应有默认 category")
	}
	if aps["sound"] != "default" {
		t.Errorf("期望 sound='default'，实际='%v'", aps["sound"])
	}
}

// TestShouldPush 验证事件类型过滤逻辑
func TestShouldPush(t *testing.T) {
	cases := []struct {
		eventType string
		expected  bool
	}{
		{"approval_required", true},
		{"task_complete", true},
		{"task_failed", true},
		{"terminal_exit", true},
		{"screen_snapshot", false},
		{"rpc_request", false},
		{"", false},
	}

	for _, tc := range cases {
		got := shouldPush(tc.eventType)
		if got != tc.expected {
			t.Errorf("shouldPush(%q) = %v，期望 %v", tc.eventType, got, tc.expected)
		}
	}
}

// TestAPNsClient_SendPush_NotConfigured 验证未配置时静默返回 nil
func TestAPNsClient_SendPush_NotConfigured(t *testing.T) {
	// bundleID 为空时应静默返回 nil
	client := NewAPNsClient("TEAM123", "KEY123", "", "")
	err := client.SendPush("device-token", "approval_required", "test")
	if err != nil {
		t.Errorf("未配置时期望 err=nil，实际 err=%v", err)
	}
}

// TestAPNsClient_SendPush_NilClient 验证 nil 客户端静默返回 nil
func TestAPNsClient_SendPush_NilClient(t *testing.T) {
	var client *APNsClient
	err := client.SendPush("device-token", "approval_required", "test")
	if err != nil {
		t.Errorf("nil 客户端期望 err=nil，实际 err=%v", err)
	}
}
