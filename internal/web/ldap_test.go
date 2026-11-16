// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/testldap"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

const (
	ldapBase   = "dc=example,dc=org"
	ldapAnnDN  = "uid=ann,ou=people," + ldapBase
	ldapAdmins = "cn=admins,ou=groups," + ldapBase
	ldapViewer = "cn=viewers,ou=groups," + ldapBase
	annUUID    = "a1b2c3d4-0000-1111-2222-333344445555"
	annPW      = "ann-directory-password-1"
	svcPW      = "svc-bind-password-SECRET"
)

// ldapRig is a fake directory plus the console settings that point at it.
type ldapRig struct {
	srv  *testldap.Server
	cfg  server.Config
	bund testtls.Bundle
}

func newLDAPRig(t *testing.T, mut func(*server.AuthLDAP)) *ldapRig {
	t.Helper()
	dir := t.TempDir()
	b, err := testtls.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := testldap.Start(testldap.Options{CertFile: b.Cert, KeyFile: b.Key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.Add("cn=svc,"+ldapBase, map[string][]string{"cn": {"svc"}})
	srv.SetPassword("cn=svc,"+ldapBase, svcPW)
	srv.Add(ldapAnnDN, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"ann"}, "cn": {"Ann Example"},
		"mail": {"ann@example.org"}, "entryUUID": {strings.ToUpper(annUUID)}, "memberOf": {ldapAdmins}})
	srv.SetPassword(ldapAnnDN, annPW)
	pwFile := filepath.Join(dir, "bind-password")
	if err := os.WriteFile(pwFile, []byte(svcPW+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := server.DefaultConfig()
	l := &cfg.Auth.LDAP
	l.Enabled, l.URL, l.StartTLS, l.CAFile = true, srv.URL(), true, b.CA
	l.BindDN, l.BindPasswordFile = "cn=svc,"+ldapBase, pwFile
	l.UserBaseDN = "ou=people," + ldapBase
	l.AdminGroups, l.ViewerGroups = []string{ldapAdmins}, []string{ldapViewer}
	l.Timeout = 2 * time.Second
	if mut != nil {
		mut(l)
	}
	return &ldapRig{srv: srv, cfg: cfg, bund: b}
}

// opt wires the rig into a console: the settings, and the directory built the way the binary builds it.
func (r *ldapRig) opt(t *testing.T) opt {
	t.Helper()
	if err := r.cfg.Validate(); err != nil {
		t.Fatalf("the rig's configuration is invalid: %v", err)
	}
	dir, err := server.BuildLDAP(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return func(d *server.Deps) {
		d.Console = r.cfg.Auth
		d.LDAP = dir
	}
}

func (e *env) auditDetails(action string) []string {
	e.t.Helper()
	raw, err := openRaw(e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT actor || ' | ' || target || ' | ' || coalesce(detail,'') FROM audit_log WHERE action=? ORDER BY id`, action)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (b *browser) loginAs(identifier, password string) page {
	b.t.Helper()
	return b.post("/login", url.Values{"email": {identifier}, "password": {password}})
}

func TestLDAPSignInCreatesTheUserAndASession(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	b := e.browser()
	if p := b.loginAs("ann", annPW); p.status != 303 || p.header.Get("Location") != "/" {
		t.Fatalf("%d %s", p.status, p.body)
	}
	home := b.get("/")
	if home.status != 200 || !strings.Contains(home.body, `data-testid="current-user">ann@example.org (admin)`) {
		t.Fatalf("%d", home.status)
	}
	if e.count(`SELECT count(*) FROM users WHERE auth_source='ldap' AND external_id=? AND external_name='ann' AND password_hash IS NULL AND role='admin'`, annUUID) != 1 {
		t.Fatal("the user row is not what an LDAP sign-in must leave")
	}
	if got := e.auditDetails("user.login"); len(got) != 1 || !strings.Contains(got[0], `"source":"ldap"`) || !strings.Contains(got[0], `"dn":"`+ldapAnnDN+`"`) {
		t.Fatalf("%v", got)
	}
	// The account page names the source and has no password or two-factor card.
	acc := b.get("/account")
	if acc.status != 200 || !strings.Contains(acc.body, `data-testid="account-source">LDAP<`) || strings.Contains(acc.body, `data-testid="account-form"`) || strings.Contains(acc.body, `account-totp-card`) {
		t.Fatalf("account page: %d\n%s", acc.status, acc.body)
	}
	// The login page of a console with LDAP reads "Email or user name" and takes a name that is no email.
	lp := e.browser().get("/login")
	if !strings.Contains(lp.body, "Email or user name") || strings.Contains(lp.body, `type="email"`) {
		t.Fatal("the login form does not offer a user name field")
	}
	// An external user cannot change a password they do not have: 403, and the CSRF token is valid.
	pc := b.post("/account/password", url.Values{"csrf_token": {csrf(t, acc)}, "current_password": {"x"}, "new_password": {"y"}, "new_password2": {"y"}})
	if pc.status != http.StatusForbidden {
		t.Fatalf("password change by an external user: %d", pc.status)
	}
}

// Decision 19: the identity is the entryUUID. After a rename (and a new mail) the SAME user signs in.
func TestLDAPRenamedEntryIsTheSameUser(t *testing.T) {
	r := newLDAPRig(t, func(l *server.AuthLDAP) { l.UserBaseDN = ldapBase })
	e := newEnv(t, r.opt(t))
	e.browser().loginAs("ann", annPW)
	r.srv.Rename(ldapAnnDN, "uid=ann,ou=staff,"+ldapBase)
	r.srv.SetAttr("uid=ann,ou=staff,"+ldapBase, "mail", "ann.new@example.org")
	if p := e.browser().loginAs("ann", annPW); p.status != 303 {
		t.Fatalf("%d", p.status)
	}
	if e.count(`SELECT count(*) FROM users`) != 1 || e.count(`SELECT count(*) FROM users WHERE email='ann.new@example.org'`) != 1 {
		t.Fatal("a rename created a second user, or the email was not refreshed")
	}
}

func TestLDAPWrongPasswordIsGenericAndThrottled(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	b := e.browser()
	for i := 0; i < 5; i++ {
		p := b.loginAs("ann", "wrong")
		if p.status != 200 || !strings.Contains(p.body, "Invalid email or password.") || e.cookieFor(b) != nil {
			t.Fatalf("attempt %d: %d", i, p.status)
		}
	}
	searches := len(r.srv.Searches())
	if p := b.loginAs("ann", annPW); p.status != 429 {
		t.Fatalf("the 6th attempt: %d, want 429", p.status)
	}
	if len(r.srv.Searches()) != searches {
		t.Fatal("a throttled attempt reached the directory")
	}
	if got := e.auditDetails("user.login.failed"); len(got) != 5 || !strings.Contains(got[0], "ldap: invalid credentials") {
		t.Fatalf("%v", got)
	}
}

// An empty password signs nobody in, and the directory sees no bind at all (an empty-password bind "succeeds").
func TestLDAPEmptyPasswordSendsNothing(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	b := e.browser()
	if p := b.loginAs("ann", ""); p.status != 200 || e.cookieFor(b) != nil || !strings.Contains(p.body, "Invalid email or password.") {
		t.Fatalf("%d", p.status)
	}
	if n := len(r.srv.Binds()) + len(r.srv.Searches()); n != 0 {
		t.Fatalf("the directory saw %d operations", n)
	}
	if e.count(`SELECT count(*) FROM users`) != 0 {
		t.Fatal("a user was created")
	}
}

func TestLDAPFilterInjectionMatchesNothing(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	b := e.browser()
	if p := b.loginAs("*)(uid=*", "anything"); p.status != 200 || e.cookieFor(b) != nil {
		t.Fatalf("%d", p.status)
	}
	ss := r.srv.Searches()
	if len(ss) != 1 || !strings.Contains(ss[0].Filter, `(uid=\2a\29\28uid=\2a)`) {
		t.Fatalf("%+v", ss)
	}
}

func TestLDAPTwoMatchingEntriesAreRefused(t *testing.T) {
	r := newLDAPRig(t, nil)
	r.srv.Add("uid=ann2,ou=people,"+ldapBase, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"ann2"}, "mail": {"ann@example.org"}, "entryUUID": {"u2"}, "memberOf": {ldapAdmins}})
	r.srv.SetPassword("uid=ann2,ou=people,"+ldapBase, annPW)
	e := newEnv(t, r.opt(t))
	b := e.browser()
	if p := b.loginAs("ann@example.org", annPW); p.status != 200 || e.cookieFor(b) != nil {
		t.Fatalf("%d", p.status)
	}
	if e.count(`SELECT count(*) FROM users`) != 0 {
		t.Fatal("a user was created from an ambiguous match")
	}
}

func TestLDAPGroupMappingAndRemoval(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	roleOf := func() string {
		raw, _ := openRaw(e.dbPath)
		defer raw.Close()
		var role string
		_ = raw.QueryRow(`SELECT role FROM users WHERE external_id=?`, annUUID).Scan(&role)
		return role
	}
	// DN case and spacing differences still map.
	r.srv.SetAttr(ldapAnnDN, "memberOf", "CN=Viewers, OU=Groups, DC=example, DC=org")
	b := e.browser()
	if b.loginAs("ann", annPW); roleOf() != "viewer" {
		t.Fatalf("role %q", roleOf())
	}
	if p := b.get("/admin/hosts"); p.status != 403 {
		t.Fatalf("a viewer reached an admin page: %d", p.status)
	}
	// Promoted at the directory: the next sign-in is admin, audited; the old session is a viewer's no longer
	// (the role is read fresh on every request).
	r.srv.SetAttr(ldapAnnDN, "memberOf", ldapViewer, ldapAdmins)
	b2 := e.browser()
	b2.loginAs("ann", annPW)
	if roleOf() != "admin" || b.get("/admin/hosts").status != 200 {
		t.Fatalf("role %q", roleOf())
	}
	if got := e.auditDetails("user.role.mapped"); len(got) != 1 || !strings.Contains(got[0], `"from":"viewer"`) || !strings.Contains(got[0], `"to":"admin"`) {
		t.Fatalf("%v", got)
	}
	// No group any more: the sign-in is refused with the "no role" page, nothing is created, no throttle count.
	r.srv.SetAttr(ldapAnnDN, "memberOf")
	for i := 0; i < 7; i++ {
		b3 := e.browser()
		p := b3.loginAs("ann", annPW)
		if p.status != 403 || !strings.Contains(p.body, `data-testid="error-no-role"`) || e.cookieFor(b3) != nil {
			t.Fatalf("attempt %d: %d", i, p.status)
		}
	}
	if got := e.auditDetails("user.login.failed"); len(got) != 7 || !strings.Contains(got[0], `"reason":"no role"`) {
		t.Fatalf("%d rows", len(got))
	}
}

// Decision 18: a local account with exactly the typed email is tried first, and LDAP is never asked.
func TestLDAPLocalFirst(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	e.addUser("ann@example.org", "viewer", goodPW, false) // the same address as ann's mail in the directory
	b := e.browser()
	b.login("ann@example.org", goodPW)
	if n := len(r.srv.Searches()) + len(r.srv.Binds()); n != 0 {
		t.Fatalf("the directory was asked (%d operations) although a local account has this email", n)
	}
	if p := b.get("/account"); !strings.Contains(p.body, "Local account") && strings.Contains(p.body, "LDAP") {
		t.Fatal("signed in as the wrong source")
	}
	// The directory's password does not open the local account (and still no directory traffic).
	b2 := e.browser()
	if p := b2.loginAs("ann@example.org", annPW); p.status != 200 || e.cookieFor(b2) != nil {
		t.Fatalf("%d", p.status)
	}
	if len(r.srv.Searches()) != 0 {
		t.Fatal("the directory was asked after a failed local check")
	}
}

// Decision 19: signing in by uid with a directory mail that belongs to a local user is refused. Nothing is
// linked, created or changed, and the local user's session survives.
func TestLDAPEmailOfALocalUserIsRefused(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	local := e.addUser("ann@example.org", "admin", goodPW, false)
	lb := e.browser()
	lb.login("ann@example.org", goodPW)
	b := e.browser()
	p := b.loginAs("ann", annPW) // by uid: the local-first rule does not apply
	if p.status != 403 || !strings.Contains(p.body, `data-testid="error-sso-unavailable"`) || e.cookieFor(b) != nil {
		t.Fatalf("%d", p.status)
	}
	if e.count(`SELECT count(*) FROM users`) != 1 || e.count(`SELECT count(*) FROM users WHERE id=? AND auth_source='local' AND role='admin' AND email='ann@example.org'`, local.ID) != 1 {
		t.Fatal("the local user changed or an external user was created")
	}
	if got := e.auditDetails("user.login.failed"); len(got) != 1 || !strings.Contains(got[0], "email in use") {
		t.Fatalf("%v", got)
	}
	if lb.get("/").status != 200 {
		t.Fatal("the local admin's session was touched")
	}
}

// The directory's fault is not the user's: a 503 page, audited, and the throttle does not count it.
func TestLDAPFaultsAre503AndDoNotCountAgainstTheUser(t *testing.T) {
	for name, brk := range map[string]func(r *ldapRig){
		"starttls refused": func(r *ldapRig) { r.srv.RefuseStartTLS(true) },
		"untrusted certificate": func(r *ldapRig) {
			// A CA file that does not vouch for the directory's certificate.
			other, _ := testtls.New(t.TempDir())
			r.cfg.Auth.LDAP.CAFile = other.CA
		},
		"directory down": func(r *ldapRig) { r.srv.Close() },
	} {
		t.Run(name, func(t *testing.T) {
			r := newLDAPRig(t, nil)
			brk(r)
			e := newEnv(t, r.opt(t))
			for i := 0; i < 7; i++ {
				b := e.browser()
				p := b.loginAs("ann", annPW)
				if p.status != http.StatusServiceUnavailable || !strings.Contains(p.body, `data-testid="error-sso-unavailable"`) || e.cookieFor(b) != nil {
					t.Fatalf("attempt %d: %d", i, p.status)
				}
			}
			if got := e.auditDetails("user.login.failed"); len(got) != 7 || !strings.Contains(got[0], "ldap: unavailable") {
				t.Fatalf("%d rows", len(got))
			}
			if bs := r.srv.Binds(); name != "directory down" && len(bs) != 0 {
				t.Fatalf("%d binds were sent: %+v", len(bs), bs)
			}
		})
	}
}

// Decision 21: LDAP users are not gated by totp_required (documented password-only), the TOTP pages refuse
// them, and a disabled user is refused at the next sign-in.
func TestLDAPUsersAreNotTOTPGatedAndCanBeDisabled(t *testing.T) {
	r := newLDAPRig(t, nil)
	r.cfg.Auth.Local.TOTPRequired = true
	e := newEnv(t, r.opt(t))
	b := e.browser()
	b.loginAs("ann", annPW)
	if p := b.get("/"); p.status != 200 {
		t.Fatalf("an LDAP user is gated: %d", p.status)
	}
	// The TOTP page only explains (the provider owns the second factor); every change is refused.
	tp := b.get("/account/totp")
	if tp.status != 200 || strings.Contains(tp.body, `data-testid="totp-setup-form"`) {
		t.Fatalf("the TOTP page for an external user: %d", tp.status)
	}
	for _, path := range []string{"/account/totp/setup", "/account/totp/confirm", "/account/totp/disable", "/account/totp/recovery-codes"} {
		if p := b.post(path, url.Values{"csrf_token": {csrf(t, tp)}, "current_password": {"x"}}); p.status != 403 {
			t.Fatalf("POST %s by an external user: %d", path, p.status)
		}
	}
	var uid int64
	raw, _ := openRaw(e.dbPath)
	_ = raw.QueryRow(`SELECT id FROM users WHERE external_id=?`, annUUID).Scan(&uid)
	raw.Close()
	if err := e.st.SetDisabled(t.Context(), uid, true, e.clock(), cliAudit); err != nil {
		t.Fatal(err)
	}
	if b.get("/").status != http.StatusSeeOther {
		t.Fatal("a disabled user's session still works")
	}
	b2 := e.browser()
	if p := b2.loginAs("ann", annPW); p.status != 200 || e.cookieFor(b2) != nil || !strings.Contains(p.body, "Invalid email or password.") {
		t.Fatalf("%d", p.status)
	}
}

// Switching LDAP off ends the LDAP users' sessions (the source is no longer enabled).
func TestLDAPSessionsEndWhenLDAPIsSwitchedOff(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	b := e.browser()
	b.loginAs("ann", annPW)
	if b.get("/").status != 200 {
		t.Fatal("not signed in")
	}
	e2 := e.another(console(nil))
	if p := carry(t, e, e2, b).get("/"); p.status != http.StatusSeeOther || p.header.Get("Location") != "/login" {
		t.Fatalf("%d %q", p.status, p.header.Get("Location"))
	}
}

// Secrets never reach a log line or an audit row: the bind password, the user's password. A DN is in the
// audit row of a SUCCESSFUL sign-in only, and never in a log line; a failed sign-in records neither.
func TestLDAPNoSecretInLogsAndAudit(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	e.browser().loginAs("ann", "wrong-"+annPW)
	e.browser().loginAs("nobody", "typed-"+annPW)
	e.browser().loginAs("ann", annPW)
	logs := e.logs.String()
	all := func() string {
		var sb strings.Builder
		for _, a := range []string{"user.login", "user.login.failed", "user.add", "user.role.mapped"} {
			sb.WriteString(strings.Join(e.auditDetails(a), "\n"))
		}
		return sb.String()
	}()
	for _, secret := range []string{svcPW, annPW, "wrong-" + annPW, "typed-" + annPW} {
		if strings.Contains(logs, secret) || strings.Contains(all, secret) {
			t.Fatalf("a secret is in the logs or the audit log: %q", secret)
		}
	}
	if strings.Contains(logs, ldapAnnDN) {
		t.Fatal("a DN is in a log line")
	}
	failed := strings.Join(e.auditDetails("user.login.failed"), "\n")
	if strings.Contains(failed, ldapAnnDN) {
		t.Fatal("the DN is in the row of a failed sign-in")
	}
	if !strings.Contains(strings.Join(e.auditDetails("user.login"), "\n"), ldapAnnDN) {
		t.Fatal("the DN is missing from the row of the successful sign-in")
	}
}


// A cookie the browser brings to the sign-in is never reused: it is deleted and a new token is issued
// (no session fixation), exactly as for a local sign-in.
func TestLDAPSignInReplacesThePresentedSession(t *testing.T) {
	r := newLDAPRig(t, nil)
	e := newEnv(t, r.opt(t))
	e.addUser("loc@example.org", "viewer", goodPW, false)
	b := e.browser()
	b.login("loc@example.org", goodPW)
	old := e.cookieFor(b)
	if old == nil {
		t.Fatal("no cookie")
	}
	if p := b.loginAs("ann", annPW); p.status != 303 {
		t.Fatalf("%d", p.status)
	}
	if now := e.cookieFor(b); now == nil || now.Value == old.Value {
		t.Fatal("the session token was reused")
	}
	if e.count(`SELECT count(*) FROM user_sessions`) != 1 {
		t.Fatalf("the presented session was not deleted: %d sessions", e.count(`SELECT count(*) FROM user_sessions`))
	}
}
