package server

import (
	"sync"

	"github.com/manaflow-ai/cmux-relay/protocol"
)

// RingBuffer 是一个线程安全的环形缓冲区，用于存储最近的消息以支持断线重连后的重放。
// screen_snapshot 类型消息会被自动过滤，不进入缓冲区。
type RingBuffer struct {
	mu   sync.RWMutex
	buf  []protocol.Envelope
	cap  int
	head int // 下一个写入位置
	size int // 当前有效元素数量
}

// NewRingBuffer 创建指定容量的环形缓冲区
func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		buf: make([]protocol.Envelope, capacity),
		cap: capacity,
	}
}

// Push 将消息推入缓冲区。
// 如果消息类型为 TypeScreenSnapshot，则直接丢弃（不存储）。
func (rb *RingBuffer) Push(msg protocol.Envelope) {
	// screen_snapshot 数据量大且客户端会主动请求，不需要缓存重放
	if msg.Type == protocol.TypeScreenSnapshot {
		return
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.buf[rb.head] = msg
	rb.head = (rb.head + 1) % rb.cap
	if rb.size < rb.cap {
		rb.size++
	}
}

// ReplaySince 返回所有 seq > lastSeq 的消息，最多返回 limit 条。
// 消息按 seq 升序排列（先进先出）。
func (rb *RingBuffer) ReplaySince(lastSeq uint64, limit int) []protocol.Envelope {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]protocol.Envelope, 0, min(rb.size, limit))

	// 计算最老消息的起始索引
	start := (rb.head - rb.size + rb.cap) % rb.cap

	for i := 0; i < rb.size; i++ {
		idx := (start + i) % rb.cap
		msg := rb.buf[idx]
		if msg.Seq > lastSeq {
			result = append(result, msg)
			if len(result) >= limit {
				break
			}
		}
	}
	return result
}

// Clear 清空缓冲区，重置所有状态
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.head = 0
	rb.size = 0
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
