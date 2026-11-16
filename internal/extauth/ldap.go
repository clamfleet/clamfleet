// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// ldap.go: LDAP sign-in by search-then-bind (docs/plans/milestone-6.md 4.16).
//
// Sequence of Directory.Authenticate, and why each step is what it is:
//  1. An empty password is refused BEFORE any network I/O. A simple bind with a name and
//     an empty password is an "unauthenticated bind" that succeeds on many servers
//     (RFC 4513 section 5.1.2): without this check anyone could sign in as anyone.
//  2. Connect over TLS 1.2 or later with verification always on. With StartTLS, a failed
//     StartTLS ends the attempt: there is no fallback to plaintext, because the next
//     message would carry the user's password. Plaintext is allowed only to loopback.
//  3. Bind as the service account (or search anonymously).
//  4. Search with the user's name ESCAPED into the filter (RFC 4515). Anything other than
//     exactly one entry is a refusal: two matching entries must never pick one at random.
//  5. Bind as the entry's DN with the typed password. invalidCredentials is a wrong
//     password; every other result is a fault of the directory, not of the user.
//  6. Groups, from the entry's own attribute or by a search as the service account.
//
// A connection per sign-in, at most four at once (a semaphore): sign-ins are rare and a
// pool is state that goes stale. Every operation is bounded by the configured timeout.
//
// This package never logs. Errors carry a reason for the audit row and a result code, never
// the password, the bind password, or a DN of a search that failed.
package extauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/clamfleet/clamfleet/internal/config"
	"github.com/clamfleet/clamfleet/internal/store"
)

// ErrRefused marks a sign-in that failed because of the user (wrong password, unknown
// user, no role, ...). The web layer shows the generic text and counts it against the
// throttle. The wrapped Reason is for the audit row only.
var ErrRefused = errors.New("sign-in refused")

// ErrUnavailable marks a fault of the directory or the network (not the user's mistake):
// the web layer shows a "try again later" page, audits it, and does not count it.
var ErrUnavailable = errors.New("directory unavailable")

// Refusal is an ErrRefused with the reason for the audit row.
type Refusal struct {
	Reason string
	// NoRole is true when the user authenticated (the password was right, or the provider vouched
	// for them) but no group or claim maps to a role. The web layer tells them so ("No role
	// assigned to your account"): it reveals nothing to someone without the credential, and it is
	// not a wrong guess, so it does not count against the throttle.
	NoRole bool
}

func (r *Refusal) Error() string { return "sign-in refused: " + r.Reason }
func (r *Refusal) Unwrap() error { return ErrRefused }

func refused(reason string) error { return &Refusal{Reason: reason} }

// Identity is what a provider vouched for: the fields of store.ExternalIdentity plus
// the DN (LDAP), which the caller may put in the audit row of a SUCCESSFUL sign-in only.
type Identity struct {
	store.ExternalIdentity
	DN string
}

// Limits of what is accepted as a typed user name.
const (
	maxUsernameBytes = 256
	maxConcurrent    = 4
)

// LDAPConfig is everything Directory needs, already resolved (files read, pool built).
type LDAPConfig struct {
	URL      string
	StartTLS bool
	// RootCAs are the trust anchors (system roots plus ca_file); nil means the system roots.
	RootCAs *x509.CertPool
	Timeout time.Duration

	BindDN, BindPassword string

	UserBaseDN, UserFilter                                        string
	IDAttribute, EmailAttribute, NameAttribute, UsernameAttribute string
	GroupAttribute, GroupBaseDN, GroupFilter                      string
	AdminGroups, ViewerGroups                                     []string
}

// Directory signs users in against one LDAP directory.
type Directory struct {
	cfg   LDAPConfig
	host  string
	tls   *tls.Config
	roles RoleMap
	sem   chan struct{}
}

// NewDirectory validates cfg and returns a Directory. It re-checks the transport rule that
// config validation also enforces, so a Directory can never be built that would send a
// password in clear to a remote host.
func NewDirectory(cfg LDAPConfig) (*Directory, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" {
		return nil, fmt.Errorf("ldap: url %q is not ldap:// or ldaps://", cfg.URL)
	}
	if u.Scheme == "ldap" && !cfg.StartTLS && !config.IsLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("ldap: plaintext is only allowed to a loopback directory (M6 decision 22)")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("ldap: a timeout is required")
	}
	if (cfg.BindDN == "") != (cfg.BindPassword == "") {
		// A bind with a DN and an empty password is an unauthenticated bind (see the file comment).
		return nil, errors.New("ldap: bind DN and bind password must be set together")
	}
	if cfg.IDAttribute == "" || cfg.UserFilter == "" || cfg.UserBaseDN == "" {
		return nil, errors.New("ldap: id attribute, user filter and user base DN are required")
	}
	return &Directory{
		cfg: cfg, host: u.Hostname(), sem: make(chan struct{}, maxConcurrent),
		// ServerName is the host of the URL; InsecureSkipVerify is never set.
		tls:   &tls.Config{ServerName: u.Hostname(), RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		roles: RoleMap{Admin: cfg.AdminGroups, Viewer: cfg.ViewerGroups, Normalize: NormalizeDN},
	}, nil
}

// CheckFilterTemplate reports whether a filter template compiles once its placeholder is
// replaced by a harmless value (used by configuration validation at start).
func CheckFilterTemplate(tmpl, placeholder string) error {
	_, err := ldap.CompileFilter(strings.ReplaceAll(tmpl, placeholder, "x"))
	return err
}

// validUsername: 1 to 256 bytes of valid UTF-8 without control characters.
func validUsername(s string) bool {
	if s == "" || len(s) > maxUsernameBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// Authenticate checks username and password against the directory. It returns the
// identity (with its role) on success, an error satisfying errors.Is(err, ErrRefused) when
// the user is refused, and one satisfying ErrUnavailable on a fault.
func (d *Directory) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	// Rule: nothing touches the network for an empty password or an unusable name (step 1).
	if password == "" {
		return Identity{}, refused("ldap: empty password")
	}
	if !validUsername(username) {
		return Identity{}, refused("ldap: invalid user name")
	}
	select {
	case d.sem <- struct{}{}:
		defer func() { <-d.sem }()
	case <-ctx.Done():
		return Identity{}, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
	}
	conn, release, err := d.connect(ctx)
	if err != nil {
		return Identity{}, err
	}
	defer release()

	if err := d.bindService(conn); err != nil {
		return Identity{}, err
	}
	// Step 4. {username} is escaped (RFC 4515): "*)(uid=*" arrives as a literal value.
	filter := strings.ReplaceAll(d.cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	attrs := uniq(d.cfg.IDAttribute, d.cfg.EmailAttribute, d.cfg.NameAttribute, d.cfg.UsernameAttribute, d.cfg.GroupAttribute)
	res, err := conn.Search(ldap.NewSearchRequest(d.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(d.cfg.Timeout.Seconds()), false, filter, attrs, nil))
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		return Identity{}, refused("ldap: no unique entry")
	case err != nil:
		return Identity{}, d.fault("search", err)
	case len(res.Entries) != 1:
		return Identity{}, refused("ldap: no unique entry")
	}
	entry := res.Entries[0]
	id := idValue(entry.GetEqualFoldRawAttributeValue(d.cfg.IDAttribute))
	if id == "" {
		return Identity{}, refused("ldap: the entry has no " + d.cfg.IDAttribute + " attribute")
	}

	// Step 5: the user's own bind is the password check.
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Identity{}, refused("ldap: invalid credentials")
		}
		return Identity{}, d.fault("bind", err)
	}

	// Step 6: groups. A search needs the service account again (the connection now belongs to the user).
	groups := entry.GetEqualFoldAttributeValues(d.cfg.GroupAttribute)
	if d.cfg.GroupAttribute == "" {
		if err := d.bindService(conn); err != nil {
			return Identity{}, err
		}
		gf := strings.ReplaceAll(d.cfg.GroupFilter, "{dn}", ldap.EscapeFilter(entry.DN))
		gres, err := conn.Search(ldap.NewSearchRequest(d.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, int(d.cfg.Timeout.Seconds()), false, gf, []string{"1.1"}, nil))
		if err != nil {
			return Identity{}, d.fault("group search", err)
		}
		for _, g := range gres.Entries {
			groups = append(groups, g.DN)
		}
	}
	role, ok := d.roles.Resolve(groups)
	if !ok {
		return Identity{}, &Refusal{Reason: "ldap: no role", NoRole: true}
	}

	out := Identity{DN: entry.DN}
	out.Source, out.ExternalID, out.Role = store.AuthLDAP, id, role
	out.ExternalName = entry.GetEqualFoldAttributeValue(d.cfg.UsernameAttribute)
	if out.ExternalName == "" {
		out.ExternalName = username
	}
	out.DisplayName = entry.GetEqualFoldAttributeValue(d.cfg.NameAttribute)
	if d.cfg.EmailAttribute != "" {
		// An address that does not pass the account-name check is treated as absent, not as a failure.
		if e, err := store.NormalizeEmail(entry.GetEqualFoldAttributeValue(d.cfg.EmailAttribute)); err == nil {
			out.Email = e
		}
	}
	return out, nil
}

// connect dials with the configured transport security (step 2).
//
// release closes the connection and ends the watch on ctx.
func (d *Directory) connect(ctx context.Context) (conn *ldap.Conn, release func(), err error) {
	dialer := &net.Dialer{Timeout: d.cfg.Timeout}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if strings.HasPrefix(d.cfg.URL, "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(d.tls))
	}
	conn, err = ldap.DialURL(d.cfg.URL, opts...)
	if err != nil {
		return nil, nil, d.fault("connect", err)
	}
	conn.SetTimeout(d.cfg.Timeout)
	// A cancelled request (the client went away) closes the connection, which unblocks any operation.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	release = func() { stop(); conn.Close() }
	if d.cfg.StartTLS {
		if err := conn.StartTLS(d.tls); err != nil {
			release()
			// Never a fallback to plaintext: the next message would carry a password.
			return nil, nil, d.fault("starttls", err)
		}
	}
	return conn, release, nil
}

// bindService binds as the service account, or does nothing for an anonymous search.
func (d *Directory) bindService(conn *ldap.Conn) error {
	if d.cfg.BindDN == "" {
		return nil
	}
	if err := conn.Bind(d.cfg.BindDN, d.cfg.BindPassword); err != nil {
		return d.fault("service bind", err)
	}
	return nil
}

// fault wraps a failure of the directory. The text carries the step and the LDAP result code
// or the network error, never a DN, a password or the server's free-text diagnostic.
func (d *Directory) fault(step string, err error) error {
	var le *ldap.Error
	if errors.As(err, &le) {
		return fmt.Errorf("%w: %s: ldap result code %d", ErrUnavailable, step, le.ResultCode)
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, step, err)
}

func uniq(names ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if n != "" && !seen[strings.ToLower(n)] {
			seen[strings.ToLower(n)] = true
			out = append(out, n)
		}
	}
	return out
}

// idValue is the stable identifier of an entry: a printable value (entryUUID) as it is, lower
// cased; a binary one (objectGUID, 16 raw bytes) as hex. Both are the same value at every
// sign-in, which is all identity needs.
func idValue(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	for _, b := range v {
		if b < 0x20 || b > 0x7e {
			return hex.EncodeToString(v)
		}
	}
	return strings.ToLower(string(v))
}
