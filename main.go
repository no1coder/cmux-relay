// cmux-relay 是一个 WebSocket 中继服务器，负责在 Mac 桌面端和 iOS 手机端之间传递消息。
package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	// 解析命令行参数
	addr := flag.String("addr", ":8443", "服务监听地址（默认 :8443）")
	db := flag.String("db", "cmux-relay.db", "SQLite 数据库文件路径")
	cert := flag.String("cert", "", "TLS 证书文件路径")
	key := flag.String("key", "", "TLS 私钥文件路径")
	flag.Parse()

	// 打印启动参数，便于调试
	fmt.Printf("cmux-relay 启动参数:\n")
	fmt.Printf("  addr : %s\n", *addr)
	fmt.Printf("  db   : %s\n", *db)
	fmt.Printf("  cert : %s\n", *cert)
	fmt.Printf("  key  : %s\n", *key)

	log.Fatal("server not implemented yet")
}
