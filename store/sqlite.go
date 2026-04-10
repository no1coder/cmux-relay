// Package store 提供基于 SQLite 的配对存储和 nonce 去重功能。
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
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
	// LiveActivityToken 是 iPhone 的 Live Activity 推送令牌
	LiveActivityToken string
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
			check_token TEXT NOT NULL DEFAULT '',
			expires_at  INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS used_nonces (
			nonce      TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS pending_pair_secrets (
			device_id   TEXT PRIMARY KEY,
			pair_secret TEXT NOT NULL,
			check_token TEXT NOT NULL DEFAULT '',
			expires_at  INTEGER NOT NULL
		);
	`)
	if err != nil {
		return err
	}
	// Live Activity token 支持
	_, _ = s.db.Exec(`ALTER TABLE pairs ADD COLUMN live_activity_token TEXT DEFAULT ''`)
	return nil
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
		SELECT device_id, device_name, phone_id, phone_name, secret_hash, apns_token,
		       COALESCE(live_activity_token, ''), created_at
		FROM pairs WHERE device_id = ?`, deviceID)
	return scanPair(row)
}

// LookupPairByPhone 通过 iPhone ID 查询配对记录
func (s *SQLiteStore) LookupPairByPhone(phoneID string) (Pair, error) {
	row := s.db.QueryRow(`
		SELECT device_id, device_name, phone_id, phone_name, secret_hash, apns_token,
		       COALESCE(live_activity_token, ''), created_at
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
		&p.LiveActivityToken,
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
// 同时生成 check_token，供 Mac 轮询 pair/check 时作为认证凭证
// deviceName 用于在配对确认时返回给 iOS 端展示，避免后续再查询
func (s *SQLiteStore) CreatePairToken(deviceID, deviceName string) (token string, checkToken string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)

	// 生成 check_token，Mac 用于轮询 pair/check 时的认证凭证
	rawCheck := make([]byte, 32)
	if _, err := rand.Read(rawCheck); err != nil {
		return "", "", err
	}
	checkToken = hex.EncodeToString(rawCheck)

	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	_, execErr := s.db.Exec(`
		INSERT INTO pair_tokens (token, device_id, device_name, check_token, expires_at) VALUES (?, ?, ?, ?, ?)`,
		token, deviceID, deviceName, checkToken, expiresAt,
	)
	if execErr != nil {
		return "", "", execErr
	}
	return token, checkToken, nil
}

// ConsumePairToken 以事务方式消费 token：验证有效性、删除记录、返回 deviceID、deviceName 和 checkToken
func (s *SQLiteStore) ConsumePairToken(token string) (deviceID, deviceName, checkToken string, err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return "", "", "", txErr
	}
	defer tx.Rollback() //nolint:errcheck

	var expiresAt int64
	scanErr := tx.QueryRow(`
		SELECT device_id, device_name, check_token, expires_at FROM pair_tokens WHERE token = ?`, token).
		Scan(&deviceID, &deviceName, &checkToken, &expiresAt)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return "", "", "", ErrTokenInvalid
	}
	if scanErr != nil {
		return "", "", "", scanErr
	}

	// 检查是否已过期
	if time.Now().Unix() > expiresAt {
		return "", "", "", ErrTokenInvalid
	}

	// 删除 token（一次性使用）
	if _, delErr := tx.Exec(`DELETE FROM pair_tokens WHERE token = ?`, token); delErr != nil {
		return "", "", "", delErr
	}

	if commitErr := tx.Commit(); commitErr != nil {
		return "", "", "", commitErr
	}
	return deviceID, deviceName, checkToken, nil
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

// UpdateLiveActivityToken 更新 Live Activity push token
func (s *SQLiteStore) UpdateLiveActivityToken(phoneID, token string) error {
	result, err := s.db.Exec(
		`UPDATE pairs SET live_activity_token = ? WHERE phone_id = ?`,
		token, phoneID,
	)
	if err != nil {
		return fmt.Errorf("update live activity token: %w", err)
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

// LookupLiveActivityToken 获取 Live Activity push token
func (s *SQLiteStore) LookupLiveActivityToken(phoneID string) (string, error) {
	row := s.db.QueryRow(`SELECT COALESCE(live_activity_token, '') FROM pairs WHERE phone_id = ?`, phoneID)
	var token string
	if err := row.Scan(&token); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrPairNotFound
		}
		return "", err
	}
	return token, nil
}

// SavePendingSecret 暂存配对密钥，供 Mac 轮询取回（有效期 5 分钟）
// checkToken 用于验证轮询方的身份，防止未授权访问
func (s *SQLiteStore) SavePendingSecret(deviceID, pairSecret, checkToken string) error {
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO pending_pair_secrets (device_id, pair_secret, check_token, expires_at)
		VALUES (?, ?, ?, ?)`,
		deviceID, pairSecret, checkToken, expiresAt,
	)
	return err
}

// ConsumePendingSecret 一次性取回暂存的配对密钥（取后即删）。
// 需要提供 checkToken 验证调用方身份，防止未授权访问。
// 未找到、已过期或 checkToken 不匹配时返回 ErrPairNotFound。
func (s *SQLiteStore) ConsumePendingSecret(deviceID, checkToken string) (pairSecret string, phoneName string, phoneID string, err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return "", "", "", txErr
	}
	defer tx.Rollback() //nolint:errcheck

	var expiresAt int64
	var storedCheckToken string
	scanErr := tx.QueryRow(`
		SELECT pair_secret, check_token, expires_at FROM pending_pair_secrets WHERE device_id = ?`, deviceID).
		Scan(&pairSecret, &storedCheckToken, &expiresAt)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return "", "", "", ErrPairNotFound
	}
	if scanErr != nil {
		return "", "", "", scanErr
	}

	if time.Now().Unix() > expiresAt {
		// 过期，删除并返回未找到
		tx.Exec(`DELETE FROM pending_pair_secrets WHERE device_id = ?`, deviceID)
		tx.Commit()
		return "", "", "", ErrPairNotFound
	}

	// 验证 check_token，防止未授权方轮询获取 pair_secret
	if storedCheckToken != checkToken {
		return "", "", "", ErrPairNotFound
	}

	// 删除记录（一次性消费）
	if _, delErr := tx.Exec(`DELETE FROM pending_pair_secrets WHERE device_id = ?`, deviceID); delErr != nil {
		return "", "", "", delErr
	}

	// 从 pairs 表获取 phone_id 和 phone_name
	scanErr = tx.QueryRow(`
		SELECT phone_id, phone_name FROM pairs WHERE device_id = ?`, deviceID).
		Scan(&phoneID, &phoneName)
	if scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
		return "", "", "", scanErr
	}

	if commitErr := tx.Commit(); commitErr != nil {
		return "", "", "", commitErr
	}
	return pairSecret, phoneName, phoneID, nil
}

// CleanExpired 删除已过期的 token、nonce 和暂存密钥记录
func (s *SQLiteStore) CleanExpired() error {
	now := time.Now().Unix()
	if _, err := s.db.Exec(`DELETE FROM pair_tokens WHERE expires_at < ?`, now); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM used_nonces WHERE expires_at < ?`, now); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM pending_pair_secrets WHERE expires_at < ?`, now); err != nil {
		return err
	}
	return nil
}
