// cmux-relay 是一个 WebSocket 中继服务器，负责在 Mac 桌面端和 iOS 手机端之间传递消息。
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/manaflow-ai/cmux-relay/server"
)

func main() {
	// 解析命令行参数
	addr := flag.String("addr", ":8443", "服务监听地址（默认 :8443）")
	dbPath := flag.String("db", "cmux-relay.db", "SQLite 数据库文件路径")
	cert := flag.String("cert", "", "TLS 证书文件路径")
	key := flag.String("key", "", "TLS 私钥文件路径")
	flag.Parse()

	// 打印启动参数，便于调试
	fmt.Printf("cmux-relay 启动参数:\n")
	fmt.Printf("  addr : %s\n", *addr)
	fmt.Printf("  db   : %s\n", *dbPath)
	fmt.Printf("  cert : %s\n", *cert)
	fmt.Printf("  key  : %s\n", *key)

	// 初始化服务器
	srv, err := server.NewServer(*dbPath)
	if err != nil {
		log.Fatalf("初始化服务器失败: %v", err)
	}

	httpSrv := &http.Server{
		Addr:    *addr,
		Handler: srv.Handler(),
	}

	// 根据是否提供 TLS 证书决定启动模式
	if *cert != "" && *key != "" {
		// 生产模式：TLS 1.3+
		httpSrv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
		log.Printf("cmux-relay 启动（TLS 模式）: %s", *addr)
		log.Fatal(httpSrv.ListenAndServeTLS(*cert, *key))
	} else {
		// 开发模式：明文 HTTP（仅用于本地测试）
		log.Printf("[警告] 未提供 TLS 证书，以开发模式启动（明文 HTTP）: %s", *addr)
		log.Fatal(httpSrv.ListenAndServe())
	}
}
