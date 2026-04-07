// Package store 提供基于 SQLite 的配对存储和 nonce 去重功能。
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// 哨兵错误定义
var (
	// ErrPairNotFound 表示配对记录不存在
	ErrPairNotFound = errors.New("store: pair not found")
	// ErrTokenInvalid 表示 pair token 无效或已过期
	ErrTokenInvalid = errors.New("store: pair token invalid or expired")
)

// Pair 表示一个 Mac 设备与 iPhone 设备的配对记录
type Pair struct {
	// DeviceID 是 Mac 设备的唯一标识
	DeviceID string
	// DeviceName 是 Mac 设备的显示名称
	DeviceName string
	// PhoneID 是 iPhone 的唯一标识
	PhoneID string
	// PhoneName 是 iPhone 的显示名称
	PhoneName string
	// SecretHash 是配对共享密钥的 SHA256 哈希
	SecretHash string
	// APNsToken 是 iPhone 的 APNs 推送令牌
	APNsToken string
	// CreatedAt 是配对创建时间
	CreatedAt time.Time
}

// SQLiteStore 是基于 SQLite 的持久化存储
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore 创建并初始化 SQLite store，dsn 可以是文件路径或 ":memory:"
func NewSQLiteStore(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	// 启用 WAL 模式和忙等待超时，提高并发性能
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		db.Close()
		return nil, err
	}

	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库连接
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// migrate 创建所需的数据库表（幂等）
func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS pairs (
			device_id   TEXT PRIMARY KEY,
			device_name TEXT NOT NULL,
			phone_id    TEXT NOT NULL UNIQUE,
			phone_name  TEXT NOT NULL,
			secret_hash TEXT NOT NULL,
			apns_token  TEXT NOT NULL,
			created_at  INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS pair_tokens (
			token       TEXT PRIMARY KEY,
			device_id   TEXT NOT NULL,
			device_name TEXT NOT NULL DEFAULT '',
			expires_at  INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS used_nonces (
			nonce      TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		);
	`)
	return err
}

// SavePair 保存或更新配对记录
func (s *SQLiteStore) SavePair(p Pair) error {
	createdAt := p.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO pairs
			(device_id, device_name, phone_id, phone_name, secret_hash, apns_token, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.DeviceID, p.DeviceName, p.PhoneID, p.PhoneName,
		p.SecretHash, p.APNsToken, createdAt.Unix(),
	)
	return err
}

// LookupPairByDevice 通过 Mac 设备 ID 查询配对记录
func (s *SQLiteStore) LookupPairByDevice(deviceID string) (Pair, error) {
	row := s.db.QueryRow(`
		SELECT device_id, device_name, phone_id, phone_name, secret_hash, apns_token, created_at
		FROM pairs WHERE device_id = ?`, deviceID)
	return scanPair(row)
}

// LookupPairByPhone 通过 iPhone ID 查询配对记录
func (s *SQLiteStore) LookupPairByPhone(phoneID string) (Pair, error) {
	row := s.db.QueryRow(`
		SELECT device_id, device_name, phone_id, phone_name, secret_hash, apns_token, created_at
		FROM pairs WHERE phone_id = ?`, phoneID)
	return scanPair(row)
}

// scanPair 从 sql.Row 扫描 Pair 结构体
func scanPair(row *sql.Row) (Pair, error) {
	var p Pair
	var createdAtUnix int64
	err := row.Scan(
		&p.DeviceID, &p.DeviceName,
		&p.PhoneID, &p.PhoneName,
		&p.SecretHash, &p.APNsToken,
		&createdAtUnix,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Pair{}, ErrPairNotFound
	}
	if err != nil {
		return Pair{}, err
	}
	p.CreatedAt = time.Unix(createdAtUnix, 0)
	return p, nil
}

// DeletePair 删除指定 Mac 设备的配对记录
func (s *SQLiteStore) DeletePair(deviceID string) error {
	result, err := s.db.Exec(`DELETE FROM pairs WHERE device_id = ?`, deviceID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrPairNotFound
	}
	return nil
}

// CreatePairToken 为指定设备生成一个随机 32 字节 hex token，有效期 5 分钟
// deviceName 用于在配对确认时返回给 iOS 端展示，避免后续再查询
func (s *SQLiteStore) CreatePairToken(deviceID, deviceName string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	_, err := s.db.Exec(`
		INSERT INTO pair_tokens (token, device_id, device_name, expires_at) VALUES (?, ?, ?, ?)`,
		token, deviceID, deviceName, expiresAt,
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

// ConsumePairToken 以事务方式消费 token：验证有效性、删除记录、返回 deviceID 和 deviceName
func (s *SQLiteStore) ConsumePairToken(token string) (deviceID, deviceName string, err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return "", "", txErr
	}
	defer tx.Rollback() //nolint:errcheck

	var expiresAt int64
	scanErr := tx.QueryRow(`
		SELECT device_id, device_name, expires_at FROM pair_tokens WHERE token = ?`, token).
		Scan(&deviceID, &deviceName, &expiresAt)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return "", "", ErrTokenInvalid
	}
	if scanErr != nil {
		return "", "", scanErr
	}

	// 检查是否已过期
	if time.Now().Unix() > expiresAt {
		return "", "", ErrTokenInvalid
	}

	// 删除 token（一次性使用）
	if _, delErr := tx.Exec(`DELETE FROM pair_tokens WHERE token = ?`, token); delErr != nil {
		return "", "", delErr
	}

	if commitErr := tx.Commit(); commitErr != nil {
		return "", "", commitErr
	}
	return deviceID, deviceName, nil
}

// TryMarkNonce 原子化地尝试标记 nonce 为已使用。
// 返回 firstUse=true 表示本次调用成功占用（首次使用），firstUse=false 表示 nonce 已存在（重放攻击）。
// 底层使用 INSERT OR IGNORE，通过 RowsAffected 判断是否真正插入，彻底消除 check-then-act 竞态。
func (s *SQLiteStore) TryMarkNonce(nonce string, expiresAt int64) (firstUse bool, err error) {
	result, err := s.db.Exec(`
		INSERT OR IGNORE INTO used_nonces (nonce, expires_at) VALUES (?, ?)`,
		nonce, expiresAt,
	)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// IsNonceUsed 检查 nonce 是否已被使用
func (s *SQLiteStore) IsNonceUsed(nonce string) (bool, error) {
	var expiresAt int64
	err := s.db.QueryRow(`
		SELECT expires_at FROM used_nonces WHERE nonce = ?`, nonce).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// 如果记录存在但已过期，视为未使用
	if time.Now().Unix() > expiresAt {
		return false, nil
	}
	return true, nil
}

// MarkNonceUsed 标记 nonce 已使用，TTL 为 60 秒
func (s *SQLiteStore) MarkNonceUsed(nonce string, ts time.Time) error {
	expiresAt := ts.Add(60 * time.Second).Unix()
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO used_nonces (nonce, expires_at) VALUES (?, ?)`,
		nonce, expiresAt,
	)
	return err
}

// UpdateAPNsToken 更新指定 phone_id 的 APNs 推送令牌
func (s *SQLiteStore) UpdateAPNsToken(phoneID, token string) error {
	result, err := s.db.Exec(
		`UPDATE pairs SET apns_token = ? WHERE phone_id = ?`,
		token, phoneID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrPairNotFound
	}
	return nil
}

// CleanExpired 删除已过期的 token 和 nonce 记录
func (s *SQLiteStore) CleanExpired() error {
	now := time.Now().Unix()
	if _, err := s.db.Exec(`DELETE FROM pair_tokens WHERE expires_at < ?`, now); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM used_nonces WHERE expires_at < ?`, now); err != nil {
		return err
	}
	return nil
}
