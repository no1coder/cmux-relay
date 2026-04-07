// Package server 提供 cmux-relay 的 WebSocket 服务器核心组件。
package server

import (
	"sync"

	"github.com/gorilla/websocket"
)

// DeviceConn 表示已连接的设备（Mac 或 iPhone）
type DeviceConn struct {
	// Conn 是底层的 WebSocket 连接
	Conn *websocket.Conn
	// writeMu 保护并发写，防止多协程同时调用 WriteMessage 导致数据竞争
	writeMu sync.Mutex
	// DeviceID 是 Mac 设备的唯一标识
	DeviceID string
	// PairID 是配对对端的 ID（Mac 侧存 PhoneID，Phone 侧存 DeviceID）
	PairID string
	// IsMac 为 true 表示是 Mac 设备，false 表示是 iPhone
	IsMac bool
}

// SafeWrite 以互斥方式向 WebSocket 连接写入消息，防止并发写冲突
func (dc *DeviceConn) SafeWrite(msgType int, data []byte) error {
	dc.writeMu.Lock()
	defer dc.writeMu.Unlock()
	return dc.Conn.WriteMessage(msgType, data)
}

// Router 管理已连接设备的路由表，并维护每对设备的消息缓冲区。
type Router struct {
	mu      sync.RWMutex
	// devices 映射 device_id → DeviceConn（Mac 端）
	devices map[string]*DeviceConn
	// phones 映射 phone_id → DeviceConn（iPhone 端）
	phones  map[string]*DeviceConn
	// buffers 映射 "device_id:phone_id" → RingBuffer（消息缓冲区）
	buffers map[string]*RingBuffer
}

// NewRouter 创建一个空的 Router
func NewRouter() *Router {
	return &Router{
		devices: make(map[string]*DeviceConn),
		phones:  make(map[string]*DeviceConn),
		buffers: make(map[string]*RingBuffer),
	}
}

// RegisterDevice 注册 Mac 设备连接
func (r *Router) RegisterDevice(conn *DeviceConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[conn.DeviceID] = conn
}

// RegisterPhone 注册 iPhone 设备连接
func (r *Router) RegisterPhone(conn *DeviceConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phones[conn.DeviceID] = conn
}

// UnregisterDevice 注销 Mac 设备连接
func (r *Router) UnregisterDevice(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.devices, deviceID)
}

// UnregisterPhone 注销 iPhone 设备连接
func (r *Router) UnregisterPhone(phoneID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.phones, phoneID)
}

// GetDevice 返回指定 deviceID 的 Mac 连接，不存在返回 nil
func (r *Router) GetDevice(deviceID string) *DeviceConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.devices[deviceID]
}

// GetPhone 返回指定 phoneID 的 iPhone 连接，不存在返回 nil
func (r *Router) GetPhone(phoneID string) *DeviceConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.phones[phoneID]
}

// IsPhoneOnline 返回指定 phoneID 是否在线
func (r *Router) IsPhoneOnline(phoneID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.phones[phoneID]
	return ok
}

// GetOrCreateBuffer 获取或创建 device+phone 对应的 RingBuffer（容量 200）
func (r *Router) GetOrCreateBuffer(deviceID, phoneID string) *RingBuffer {
	key := deviceID + ":" + phoneID
	r.mu.Lock()
	defer r.mu.Unlock()
	if buf, ok := r.buffers[key]; ok {
		return buf
	}
	buf := NewRingBuffer(200)
	r.buffers[key] = buf
	return buf
}
