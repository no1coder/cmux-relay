package server_test

import (
	"encoding/json"
	"testing"

	"github.com/manaflow-ai/cmux-relay/protocol"
	"github.com/manaflow-ai/cmux-relay/server"
)

// makeEnvelope 创建一个用于测试的 Envelope
func makeEnvelope(seq uint64, msgType protocol.MessageType) protocol.Envelope {
	return protocol.Envelope{
		Seq:     seq,
		Ts:      int64(seq) * 1000,
		From:    protocol.OriginMac,
		Type:    msgType,
		Payload: json.RawMessage(`{"data":"test"}`),
	}
}

// TestRingBuffer_PushAndReplay 测试推送 3 条消息后 replay 全部返回
func TestRingBuffer_PushAndReplay(t *testing.T) {
	rb := server.NewRingBuffer(10)

	for i := uint64(1); i <= 3; i++ {
		rb.Push(makeEnvelope(i, protocol.TypeEvent))
	}

	items := rb.ReplaySince(0, 100)
	if len(items) != 3 {
		t.Errorf("期望 3 条消息, 得到 %d", len(items))
	}
	// 验证序列号顺序
	for i, item := range items {
		if item.Seq != uint64(i+1) {
			t.Errorf("第 %d 条消息期望 seq=%d, 得到 %d", i, i+1, item.Seq)
		}
	}
}

// TestRingBuffer_Overflow 测试容量为 3 时推送 5 条只保留最后 3 条
func TestRingBuffer_Overflow(t *testing.T) {
	rb := server.NewRingBuffer(3)

	for i := uint64(1); i <= 5; i++ {
		rb.Push(makeEnvelope(i, protocol.TypeEvent))
	}

	items := rb.ReplaySince(0, 100)
	if len(items) != 3 {
		t.Errorf("期望 3 条消息（溢出后）, 得到 %d", len(items))
	}
	// 应保留 seq 3, 4, 5
	expectedSeqs := []uint64{3, 4, 5}
	for i, item := range items {
		if item.Seq != expectedSeqs[i] {
			t.Errorf("第 %d 条期望 seq=%d, 得到 %d", i, expectedSeqs[i], item.Seq)
		}
	}
}

// TestRingBuffer_ReplaySinceSeq 测试 ReplaySince 只返回 seq > lastSeq 的消息
func TestRingBuffer_ReplaySinceSeq(t *testing.T) {
	rb := server.NewRingBuffer(10)

	for i := uint64(1); i <= 5; i++ {
		rb.Push(makeEnvelope(i, protocol.TypeEvent))
	}

	// 从 seq=3 开始，应返回 seq 4 和 5
	items := rb.ReplaySince(3, 100)
	if len(items) != 2 {
		t.Errorf("期望 2 条消息, 得到 %d", len(items))
	}
	if items[0].Seq != 4 {
		t.Errorf("期望第一条 seq=4, 得到 %d", items[0].Seq)
	}
	if items[1].Seq != 5 {
		t.Errorf("期望第二条 seq=5, 得到 %d", items[1].Seq)
	}
}

// TestRingBuffer_PageLimit 测试 limit 参数截断返回结果
func TestRingBuffer_PageLimit(t *testing.T) {
	rb := server.NewRingBuffer(100)

	for i := uint64(1); i <= 50; i++ {
		rb.Push(makeEnvelope(i, protocol.TypeEvent))
	}

	items := rb.ReplaySince(0, 10)
	if len(items) != 10 {
		t.Errorf("期望 10 条消息（分页限制）, 得到 %d", len(items))
	}
	// 应返回最早的 10 条（seq 1-10）
	if items[0].Seq != 1 {
		t.Errorf("期望第一条 seq=1, 得到 %d", items[0].Seq)
	}
	if items[9].Seq != 10 {
		t.Errorf("期望最后一条 seq=10, 得到 %d", items[9].Seq)
	}
}

// TestRingBuffer_SkipScreenSnapshot 测试 screen_snapshot 类型消息不进入缓冲区
func TestRingBuffer_SkipScreenSnapshot(t *testing.T) {
	rb := server.NewRingBuffer(10)

	rb.Push(makeEnvelope(1, protocol.TypeEvent))
	rb.Push(makeEnvelope(2, protocol.TypeScreenSnapshot)) // 应被跳过
	rb.Push(makeEnvelope(3, protocol.TypeEvent))

	items := rb.ReplaySince(0, 100)
	if len(items) != 2 {
		t.Errorf("期望 2 条消息（跳过 snapshot）, 得到 %d", len(items))
	}
	if items[0].Seq != 1 {
		t.Errorf("期望第一条 seq=1, 得到 %d", items[0].Seq)
	}
	if items[1].Seq != 3 {
		t.Errorf("期望第二条 seq=3, 得到 %d", items[1].Seq)
	}
}
