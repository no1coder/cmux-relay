package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/manaflow-ai/cmux-relay/store"
)

// wsUpgrader 将 HTTP 连接升级为 WebSocket，使用 4096 字节缓冲区
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// 允许所有来源，由业务层（HMAC 认证）保证安全性
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Server 组合了所有服务组件，对外提供 HTTP + WebSocket 路由
type Server struct {
	store   *store.SQLiteStore
	router  *Router
	relay   *Relay
	pairing *PairHandler
}

// NewServer 创建并初始化 Server，dbPath 为 SQLite 数据库文件路径
func NewServer(dbPath string) (*Server, error) {
	// 初始化 SQLite store
	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		return nil, err
	}

	// 初始化路由表
	r := NewRouter()

	// 认证器，允许最大 10 秒时间漂移
	auth := NewAuthenticator(10 * time.Second)

	// 中继引擎
	relay := NewRelay(s, r, auth)

	// 配对 API 处理器
	pairing := NewPairHandler(s, r)

	srv := &Server{
		store:   s,
		router:  r,
		relay:   relay,
		pairing: pairing,
	}

	// 启动后台任务：每分钟清理过期 token 和 nonce
	go srv.startCleanup()

	return srv, nil
}

// startCleanup 每分钟清理过期的 pair token 和 nonce
func (srv *Server) startCleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if err := srv.store.CleanExpired(); err != nil {
			log.Printf("[server] CleanExpired error: %v", err)
		}
	}
}

// Handler 返回配置了所有路由的 http.Handler
func (srv *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 健康检查
	mux.HandleFunc("/health", srv.handleHealth)

	// 配对 REST API
	mux.HandleFunc("/api/pair/init", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.pairing.HandlePairInit(w, r)
	})
	mux.HandleFunc("/api/pair/confirm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.pairing.HandlePairConfirm(w, r)
	})
	mux.HandleFunc("/api/pair/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.pairing.HandlePairDelete(w, r)
	})

	// APNs push token 存储（存根，后续实现）
	mux.HandleFunc("/api/push/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})

	// WebSocket 端点
	mux.HandleFunc("/ws/device/", srv.handleDeviceWS)
	mux.HandleFunc("/ws/phone/", srv.handlePhoneWS)

	return mux
}

// handleHealth 返回服务健康状态
func (srv *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleDeviceWS 升级 Mac 设备的 WebSocket 连接
func (srv *Server) handleDeviceWS(w http.ResponseWriter, r *http.Request) {
	// 从 URL path 提取 device_id：/ws/device/{device_id}
	deviceID := strings.TrimPrefix(r.URL.Path, "/ws/device/")
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		http.Error(w, "device_id is required", http.StatusBadRequest)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] WS upgrade error device=%s: %v", deviceID, err)
		return
	}

	go srv.relay.HandleDeviceWS(conn, deviceID)
}

// handlePhoneWS 升级 iPhone 的 WebSocket 连接
func (srv *Server) handlePhoneWS(w http.ResponseWriter, r *http.Request) {
	// 从 URL path 提取 phone_id：/ws/phone/{phone_id}
	phoneID := strings.TrimPrefix(r.URL.Path, "/ws/phone/")
	phoneID = strings.TrimSpace(phoneID)
	if phoneID == "" {
		http.Error(w, "phone_id is required", http.StatusBadRequest)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] WS upgrade error phone=%s: %v", phoneID, err)
		return
	}

	go srv.relay.HandlePhoneWS(conn, phoneID)
}
