package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/manaflow-ai/cmux-relay/protocol"
)

// TestEnvelopeMarshalUnmarshal 验证 Envelope 的序列化和反序列化往返一致性
func TestEnvelopeMarshalUnmarshal(t *testing.T) {
	payload := json.RawMessage(`{"key":"value","num":42}`)

	original := protocol.Envelope{
		Seq:     1,
		Ts:      1700000000,
		From:    protocol.OriginMac,
		Type:    protocol.TypeRPCRequest,
		Payload: payload,
	}

	// 序列化
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}

	// 反序列化
	var decoded protocol.Envelope
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal 失败: %v", err)
	}

	// 验证字段
	if decoded.Seq != original.Seq {
		t.Errorf("Seq 不匹配: got %d, want %d", decoded.Seq, original.Seq)
	}
	if decoded.Ts != original.Ts {
		t.Errorf("Ts 不匹配: got %d, want %d", decoded.Ts, original.Ts)
	}
	if decoded.From != original.From {
		t.Errorf("From 不匹配: got %q, want %q", decoded.From, original.From)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type 不匹配: got %q, want %q", decoded.Type, original.Type)
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Payload 不匹配: got %s, want %s", decoded.Payload, original.Payload)
	}
}

// TestEnvelopeValidateSuccess 验证合法的 Envelope 不报错
func TestEnvelopeValidateSuccess(t *testing.T) {
	env := protocol.Envelope{
		Seq:     1,
		Ts:      1700000000,
		From:    protocol.OriginPhone,
		Type:    protocol.TypeEvent,
		Payload: json.RawMessage(`{"data":"test"}`),
	}

	if err := env.Validate(); err != nil {
		t.Errorf("合法 Envelope 不应报错, 但得到: %v", err)
	}
}

// TestEnvelopeValidateEmptyFrom 验证 From 为空时报错
func TestEnvelopeValidateEmptyFrom(t *testing.T) {
	env := protocol.Envelope{
		Seq:     1,
		Ts:      1700000000,
		From:    "",
		Type:    protocol.TypeRPCRequest,
		Payload: json.RawMessage(`{"data":"test"}`),
	}

	if err := env.Validate(); err == nil {
		t.Error("From 为空时应返回错误")
	}
}

// TestEnvelopeValidateEmptyType 验证 Type 为空时报错
func TestEnvelopeValidateEmptyType(t *testing.T) {
	env := protocol.Envelope{
		Seq:     1,
		Ts:      1700000000,
		From:    protocol.OriginMac,
		Type:    "",
		Payload: json.RawMessage(`{"data":"test"}`),
	}

	if err := env.Validate(); err == nil {
		t.Error("Type 为空时应返回错误")
	}
}

// TestEnvelopeValidateNilPayload 验证 Payload 为 nil 时报错
func TestEnvelopeValidateNilPayload(t *testing.T) {
	env := protocol.Envelope{
		Seq:     1,
		Ts:      1700000000,
		From:    protocol.OriginMac,
		Type:    protocol.TypeRPCRequest,
		Payload: nil,
	}

	if err := env.Validate(); err == nil {
		t.Error("Payload 为 nil 时应返回错误")
	}
}

// TestEnvelopeAllMessageTypes 验证所有消息类型常量都可以被使用
func TestEnvelopeAllMessageTypes(t *testing.T) {
	types := []protocol.MessageType{
		protocol.TypeRPCRequest,
		protocol.TypeRPCResponse,
		protocol.TypeEvent,
		protocol.TypeScreenSnapshot,
		protocol.TypeResume,
		protocol.TypeAuth,
	}

	for _, msgType := range types {
		env := protocol.Envelope{
			Seq:     1,
			Ts:      1700000000,
			From:    protocol.OriginMac,
			Type:    msgType,
			Payload: json.RawMessage(`{}`),
		}
		if err := env.Validate(); err != nil {
			t.Errorf("消息类型 %q 应该有效, 但得到错误: %v", msgType, err)
		}
	}
}

// TestOriginConstants 验证 Origin 常量值正确
func TestOriginConstants(t *testing.T) {
	if protocol.OriginMac != "mac" {
		t.Errorf("OriginMac 应为 'mac', 得到 %q", protocol.OriginMac)
	}
	if protocol.OriginPhone != "phone" {
		t.Errorf("OriginPhone 应为 'phone', 得到 %q", protocol.OriginPhone)
	}
}
