package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Roles, in increasing order of privilege.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// RoleRank orders roles for "at least" checks.
func RoleRank(r string) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

// User is a local account.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         string
	TOTPSecret   string // encrypted at rest
	Disabled     bool
	CreatedAt    time.Time
	LastLogin    time.Time
}

// Session is a browser login session.
type Session struct {
	IDHash     string
	UserID     string
	CSRFToken  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeen   time.Time
	MFAPending bool
}

// APIToken is a scoped automation token.
type APIToken struct {
	ID        string
	UserID    string
	Name      string
	Scope     string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time
}

const userCols = `id, username, password_hash, role, totp_secret, disabled, created_at, last_login`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var dis int
	var c, l int64
	err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.TOTPSecret, &dis, &c, &l)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.Disabled, u.CreatedAt = dis != 0, time.Unix(c, 0)
	if l > 0 {
		u.LastLogin = time.Unix(l, 0)
	}
	return u, err
}

// CreateUser inserts a user.
func (d *DB) CreateUser(ctx context.Context, username, hash, role string) (User, error) {
	u := User{ID: uuid.NewString(), Username: username, PasswordHash: hash, Role: role, CreatedAt: d.now()}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO users(id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)`,
		u.ID, username, hash, role, u.CreatedAt.Unix())
	return u, err
}

// CountUsers returns the number of users.
func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// GetUser returns a user by ID.
func (d *DB) GetUser(ctx context.Context, id string) (User, error) {
	return scanUser(d.sql.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// GetUserByName returns a user by username.
func (d *DB) GetUserByName(ctx context.Context, name string) (User, error) {
	return scanUser(d.sql.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

// ListUsers returns all users.
func (d *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser saves role, disabled, password hash and TOTP secret.
func (d *DB) UpdateUser(ctx context.Context, u User) error {
	dis := 0
	if u.Disabled {
		dis = 1
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ?, password_hash = ?, totp_secret = ? WHERE id = ?`,
		u.Role, dis, u.PasswordHash, u.TOTPSecret, u.ID)
	return err
}

// DeleteUser removes a user.
func (d *DB) DeleteUser(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// TouchLogin records a successful login.
func (d *DB) TouchLogin(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE users SET last_login = ? WHERE id = ?`, d.now().Unix(), id)
	return err
}

// CreateSession stores a session.
func (d *DB) CreateSession(ctx context.Context, s Session, addr, ua string) error {
	mfa := 0
	if s.MFAPending {
		mfa = 1
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO sessions(id_hash, user_id, csrf_token, created_at, expires_at, last_seen, mfa_pending, remote_addr, user_agent) VALUES (?,?,?,?,?,?,?,?,?)`,
		s.IDHash, s.UserID, s.CSRFToken, s.CreatedAt.Unix(), s.ExpiresAt.Unix(), s.LastSeen.Unix(), mfa, addr, ua)
	return err
}

// GetSession returns a non-expired session.
func (d *DB) GetSession(ctx context.Context, idHash string) (Session, error) {
	var s Session
	var c, e, l int64
	var mfa int
	err := d.sql.QueryRowContext(ctx, `SELECT id_hash, user_id, csrf_token, created_at, expires_at, last_seen, mfa_pending FROM sessions WHERE id_hash = ? AND expires_at > ?`,
		idHash, d.now().Unix()).Scan(&s.IDHash, &s.UserID, &s.CSRFToken, &c, &e, &l, &mfa)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	s.CreatedAt, s.ExpiresAt, s.LastSeen, s.MFAPending = time.Unix(c, 0), time.Unix(e, 0), time.Unix(l, 0), mfa != 0
	return s, err
}

// TouchSession extends an idle session.
func (d *DB) TouchSession(ctx context.Context, idHash string, expires time.Time) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE sessions SET last_seen = ?, expires_at = ? WHERE id_hash = ?`, d.now().Unix(), expires.Unix(), idHash)
	return err
}

// CompleteMFA clears the pending-MFA flag.
func (d *DB) CompleteMFA(ctx context.Context, idHash string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE sessions SET mfa_pending = 0 WHERE id_hash = ?`, idHash)
	return err
}

// DeleteSession logs a session out.
func (d *DB) DeleteSession(ctx context.Context, idHash string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteUserSessions logs a user out everywhere.
func (d *DB) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// PruneSessions deletes expired sessions.
func (d *DB) PruneSessions(ctx context.Context) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, d.now().Unix())
	return err
}

// CreateAPIToken stores a token hash.
func (d *DB) CreateAPIToken(ctx context.Context, tokenHash, userID, name, scope string, ttl time.Duration) (APIToken, error) {
	t := APIToken{ID: uuid.NewString(), UserID: userID, Name: name, Scope: scope, CreatedAt: d.now()}
	var exp int64
	if ttl > 0 {
		t.ExpiresAt = t.CreatedAt.Add(ttl)
		exp = t.ExpiresAt.Unix()
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO api_tokens(id, token_hash, user_id, name, scope, created_at, expires_at) VALUES (?,?,?,?,?,?,?)`,
		t.ID, tokenHash, userID, name, scope, t.CreatedAt.Unix(), exp)
	return t, err
}

// LookupAPIToken resolves a token hash to the token and its user.
func (d *DB) LookupAPIToken(ctx context.Context, tokenHash string) (APIToken, User, error) {
	var t APIToken
	var c, e int64
	err := d.sql.QueryRowContext(ctx, `SELECT id, user_id, name, scope, created_at, expires_at FROM api_tokens WHERE token_hash = ?`, tokenHash).
		Scan(&t.ID, &t.UserID, &t.Name, &t.Scope, &c, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return t, User{}, ErrNotFound
	}
	if err != nil {
		return t, User{}, err
	}
	t.CreatedAt = time.Unix(c, 0)
	if e > 0 {
		t.ExpiresAt = time.Unix(e, 0)
		if d.now().After(t.ExpiresAt) {
			return t, User{}, ErrNotFound
		}
	}
	u, err := d.GetUser(ctx, t.UserID)
	if err != nil {
		return t, u, err
	}
	_, _ = d.sql.ExecContext(ctx, `UPDATE api_tokens SET last_used = ? WHERE id = ?`, d.now().Unix(), t.ID)
	return t, u, nil
}

// ListAPITokens lists tokens (optionally for one user).
func (d *DB) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	q := `SELECT id, user_id, name, scope, created_at, expires_at, last_used FROM api_tokens`
	args := []any{}
	if userID != "" {
		q += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	rows, err := d.sql.QueryContext(ctx, q+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var c, e, l int64
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Scope, &c, &e, &l); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(c, 0)
		if e > 0 {
			t.ExpiresAt = time.Unix(e, 0)
		}
		if l > 0 {
			t.LastUsed = time.Unix(l, 0)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes a token (scoped to user unless userID is empty).
func (d *DB) DeleteAPIToken(ctx context.Context, id, userID string) error {
	if userID == "" {
		_, err := d.sql.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
		return err
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ? AND user_id = ?`, id, userID)
	return err
}
