//go:build e2e_idp && !e2e

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Identity-provider interoperability, run in the throwaway clamfleet-idp
// container by `make e2e-idp`: the REAL server binary signs users in against a REAL OpenLDAP (StartTLS,
// the memberOf overlay) and a REAL Keycloak (authorization code flow with PKCE, a groups mapper). The
// in-process fakes (internal/testldap, internal/testoidc) test our side of the protocol; this proves the
// other side behaves the way the fakes assume.
//
// Everything runs INSIDE the container, so nothing is exposed: the server listens on 127.0.0.1:8443 there,
// slapd on 127.0.0.1:389 and Keycloak on 127.0.0.1:8080. The sign-ins are made by a small Go program
// (e2e/idpdriver) pushed into the container, which plays a browser: it posts the console's form, and for
// OIDC submits Keycloak's login form (parsing the action out of the page). The suite reads the result and
// the user list back through the server's own CLI.
//
// Built with -tags e2e_idp, WITHOUT the e2e tag: the container has no clamd, and the other suite's TestMain
// restores a ClamAV snapshot. A missing CFT_EXEC fails, it never skips (the Makefile sets it from CFI_EXEC).
//
// Active Directory is NOT tested (there is no Samba AD DC here): docs/auth.md marks it "configuration
// documented, untested".
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/testtls"
)

// The test-only credentials of the container (docs/testing.md "The IdP container").
const (
	ldapBase    = "dc=example,dc=test"
	ldapBindDN  = "cn=clamfleet-ro," + ldapBase
	ldapBindPW  = "ro-test-pw"
	oidcIssuer  = "http://127.0.0.1:8080/realms/clamfleet"
	oidcSecret  = "clamfleet-oidc-test-secret"
	consoleURL  = "https://127.0.0.1:8443"
	serverUnit  = "clamfleet-server-idp"
	adminsGroup = "clamfleet-admins"
	viewerGroup = "clamfleet-viewers"
)

var (
	cftExec  []string
	srvBin   string
	drvBin   string
	repoRoot string
)

func TestMain(m *testing.M) { os.Exit(testMain(m)) }

func testMain(m *testing.M) int {
	cftExec = strings.Fields(os.Getenv("CFT_EXEC"))
	if len(cftExec) == 0 {
		fmt.Fprintln(os.Stderr, "e2e-idp: CFT_EXEC is not set (make e2e-idp sets it from CFI_EXEC: the command prefix that runs a command inside clamfleet-idp); see docs/testing.md")
		return 1
	}
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e-idp: go list:", err)
		return 1
	}
	repoRoot = strings.TrimSpace(string(out))
	dir, err := os.MkdirTemp("", "cfe2eidp")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	srvBin, drvBin = filepath.Join(dir, "clamfleet-server"), filepath.Join(dir, "idpdriver")
	for out, pkg := range map[string]string{srvBin: "cmd/clamfleet-server", drvBin: "e2e/idpdriver"} {
		cmd := exec.Command("go", "build", "-trimpath", "-o", out, "github.com/clamfleet/clamfleet/"+pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if o, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e-idp: build %s: %v\n%s", pkg, err, o)
			return 1
		}
	}
	code := m.Run()
	// Leave the container as found, even when a test failed half way.
	if err := script("idp-prepare.sh"); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-idp: final reset failed:", err)
		code = 1
	}
	return code
}

func script(name string) error {
	cmd := exec.Command(filepath.Join(repoRoot, "deploy", "test", name))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w\n%s", name, err, out)
	}
	return nil
}

// ct runs a command inside the container (arguments without spaces or shell syntax: ssh re-parses them).
func ct(ctx context.Context, stdin []byte, args ...string) (stdout, stderr string, code int) {
	cmd := exec.CommandContext(ctx, cftExec[0], append(append([]string{}, cftExec[1:]...), args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		code = -1
		se.WriteString(err.Error())
	}
	return so.String(), se.String(), code
}

// sh runs a shell script as root in the container and returns its stdout; a failure fails the test.
func sh(t *testing.T, scriptText string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, errOut, code := ct(ctx, []byte("set -eu\n"+scriptText), "bash", "-s")
	if code != 0 {
		t.Fatalf("container script failed (exit %d): %s\nstdout: %s\nstderr: %s", code, scriptText, out, errOut)
	}
	return strings.TrimSpace(out)
}

func pushBinary(t *testing.T, path, name string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tarball bytes.Buffer
	tw := tar.NewWriter(&tarball)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, e, code := ct(ctx, tarball.Bytes(), "tar", "-xf", "-", "-C", "/usr/local/bin", "--no-same-owner"); code != 0 {
		t.Fatalf("pushing %s: exit %d: %s", name, code, e)
	}
}

// serverConfig is the server's configuration inside the container: both providers on, StartTLS to
// slapd with the test CA, Keycloak over plain http on loopback (allowed for a loopback issuer only).
const serverConfig = `listen: 127.0.0.1:8443
tls:
  cert: /etc/clamfleet/tls.crt
  key: /etc/clamfleet/tls.key
db_path: /var/lib/clamfleet-server/clamfleet.db
secret_key_file: /etc/clamfleet/server-secret.key
public_url: ` + consoleURL + `
auth:
  ldap:
    enabled: true
    url: ldap://127.0.0.1:389
    start_tls: true
    ca_file: /etc/clamfleet-idp/ca.crt
    bind_dn: ` + ldapBindDN + `
    bind_password_file: /etc/clamfleet/ldap-bind-password
    user_base_dn: ou=people,` + ldapBase + `
    admin_groups: ["cn=` + adminsGroup + `,ou=groups,` + ldapBase + `"]
    viewer_groups: ["cn=` + viewerGroup + `,ou=groups,` + ldapBase + `"]
  oidc:
    enabled: true
    issuer: ` + oidcIssuer + `
    client_id: clamfleet
    client_secret_file: /etc/clamfleet/oidc-client-secret
    admin_values: [` + adminsGroup + `]
    viewer_values: [` + viewerGroup + `]
`

// idpFresh restores the container, pushes the binaries and starts the real server configured for both
// providers. The console's certificate is for 127.0.0.1; its CA is /etc/clamfleet/ca.pem for the driver.
func idpFresh(t *testing.T) {
	t.Helper()
	if err := script("idp-prepare.sh"); err != nil {
		t.Fatal(err)
	}
	pushBinary(t, srvBin, "clamfleet-server")
	pushBinary(t, drvBin, "idpdriver")
	b, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) string {
		d, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(d)
	}
	// PEM and the configuration are plain text, so heredocs carry them safely over stdin.
	sh(t, `getent passwd clamfleet-server >/dev/null || useradd --system --home-dir /var/lib/clamfleet-server --create-home --shell /usr/sbin/nologin clamfleet-server
mkdir -p /etc/clamfleet; chown root:clamfleet-server /etc/clamfleet; chmod 0750 /etc/clamfleet
chmod 0700 /var/lib/clamfleet-server; chown clamfleet-server: /var/lib/clamfleet-server
cat > /etc/clamfleet/ca.pem <<'CF_EOF'
`+read(b.CA)+`CF_EOF
cat > /etc/clamfleet/tls.crt <<'CF_EOF'
`+read(b.Cert)+`CF_EOF
cat > /etc/clamfleet/tls.key <<'CF_EOF'
`+read(b.Key)+`CF_EOF
chmod 644 /etc/clamfleet/ca.pem /etc/clamfleet/tls.crt
chown clamfleet-server: /etc/clamfleet/tls.key; chmod 600 /etc/clamfleet/tls.key
printf '%s\n' '`+ldapBindPW+`' > /etc/clamfleet/ldap-bind-password
printf '%s\n' '`+oidcSecret+`' > /etc/clamfleet/oidc-client-secret
chown root:clamfleet-server /etc/clamfleet/ldap-bind-password /etc/clamfleet/oidc-client-secret
chmod 0640 /etc/clamfleet/ldap-bind-password /etc/clamfleet/oidc-client-secret
cat > /etc/clamfleet/server.yaml <<'CF_EOF'
`+serverConfig+`CF_EOF
chown root:clamfleet-server /etc/clamfleet/server.yaml; chmod 0640 /etc/clamfleet/server.yaml
/usr/local/bin/clamfleet-server key generate 2>/dev/null
chgrp clamfleet-server /etc/clamfleet/server-secret.key; chmod 0640 /etc/clamfleet/server-secret.key
runuser -u clamfleet-server -- /usr/local/bin/clamfleet-server migrate
listening() { journalctl -u `+serverUnit+` -o cat --no-pager -q | grep -c '"msg":"listening"' || true; }
n=$(listening)
systemd-run --quiet --collect --unit=`+serverUnit+` --uid=clamfleet-server /usr/local/bin/clamfleet-server serve
for _ in $(seq 1 30); do [ "$(listening)" -gt "$n" ] && exit 0; sleep 1; done
journalctl -u `+serverUnit+` --no-pager >&2; echo server did not start >&2; exit 1
`)
}

// result mirrors e2e/idpdriver.Result.
type result struct {
	Status        int      `json:"status"`
	SignedIn      bool     `json:"signed_in"`
	CurrentUser   string   `json:"current_user"`
	AccountSource string   `json:"account_source"`
	AdminPage     int      `json:"admin_page"`
	TestIDs       []string `json:"test_ids"`
	ErrorText     string   `json:"error_text"`
}

func (r result) has(testID string) bool {
	for _, id := range r.TestIDs {
		if id == testID {
			return true
		}
	}
	return false
}

// drive signs in through the console inside the container.
func drive(t *testing.T, mode, user, password string) result {
	t.Helper()
	out := sh(t, "/usr/local/bin/idpdriver "+mode+" --url "+consoleURL+" --ca /etc/clamfleet/ca.pem --user "+user+" --password "+password)
	var r result
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("driver output %q: %v", out, err)
	}
	return r
}

type listedUser struct {
	Email        string `json:"email"`
	Role         string `json:"role"`
	AuthSource   string `json:"auth_source"`
	ExternalName string `json:"external_name"`
	ExternalID   string `json:"external_id"`
}

func users(t *testing.T) []listedUser {
	t.Helper()
	out := sh(t, "runuser -u clamfleet-server -- /usr/local/bin/clamfleet-server user list --json")
	var us []listedUser
	if err := json.Unmarshal([]byte(out), &us); err != nil {
		t.Fatalf("user list: %v\n%s", err, out)
	}
	return us
}

func userNamed(us []listedUser, name string) (listedUser, int) {
	var found listedUser
	n := 0
	for _, u := range us {
		if u.ExternalName == name {
			found, n = u, n+1
		}
	}
	return found, n
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestLDAPAgainstOpenLDAP(t *testing.T) {
	idpFresh(t)

	// alice is in the admin group: signed in, admin, source LDAP.
	a := drive(t, "ldap", "alice", "alice-test-pw")
	if !a.SignedIn || a.CurrentUser != "alice@example.test (admin)" || a.AccountSource != "LDAP" || a.AdminPage != 200 {
		t.Fatalf("alice: %+v", a)
	}
	// bob is a viewer: no admin page.
	b := drive(t, "ldap", "bob", "bob-test-pw")
	if !b.SignedIn || b.CurrentUser != "bob@example.test (viewer)" || b.AdminPage != 403 {
		t.Fatalf("bob: %+v", b)
	}
	// carol is in no group: refused with the "no role" page, and no user is created for her.
	c := drive(t, "ldap", "carol", "carol-test-pw")
	if c.SignedIn || c.Status != 403 || !c.has("error-no-role") {
		t.Fatalf("carol: %+v", c)
	}
	// A wrong password: the generic text, no session.
	w := drive(t, "ldap", "alice", "not-the-password")
	if w.SignedIn || !strings.Contains(w.ErrorText, "Invalid email or password.") {
		t.Fatalf("wrong password: %+v", w)
	}
	// By mail as well as by uid (the default filter), and the same user row.
	if r := drive(t, "ldap", "alice@example.test", "alice-test-pw"); !r.SignedIn {
		t.Fatalf("by mail: %+v", r)
	}

	// The identity is the entryUUID, never the DN.
	uuid := strings.ToLower(strings.TrimSpace(sh(t, `ldapsearch -Y EXTERNAL -H ldapi:/// -LLL -b uid=alice,ou=people,`+ldapBase+` -s base entryUUID 2>/dev/null | sed -n 's/^entryUUID: //p'`)))
	us := users(t)
	alice, n := userNamed(us, "alice")
	if n != 1 || alice.AuthSource != "ldap" || alice.ExternalID != uuid || !uuidRE.MatchString(uuid) || alice.Role != "admin" {
		t.Fatalf("alice: %d rows, %+v, entryUUID %q", n, alice, uuid)
	}
	if _, n := userNamed(us, "carol"); n != 0 {
		t.Fatal("a user in no group was created")
	}

	// Groups change at the directory: alice moves from the admin group to the viewer group (the memberOf
	// overlay follows). The next sign-in is a viewer, on the same row. A groupOfNames needs a member, so
	// the service account is added to the admin group first.
	// The root of the container (SASL EXTERNAL over ldapi) manages cn=config only, so the test first gives it
	// manage rights on the data database; the container is restored from its snapshot before every scenario.
	sh(t, `ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<'CF_EOF'
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to * by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage by * break
CF_EOF
ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<'CF_EOF'
dn: cn=`+adminsGroup+`,ou=groups,`+ldapBase+`
changetype: modify
add: member
member: `+ldapBindDN+`
-
delete: member
member: uid=alice,ou=people,`+ldapBase+`

dn: cn=`+viewerGroup+`,ou=groups,`+ldapBase+`
changetype: modify
add: member
member: uid=alice,ou=people,`+ldapBase+`
CF_EOF`)
	again := drive(t, "ldap", "alice", "alice-test-pw")
	if !again.SignedIn || again.CurrentUser != "alice@example.test (viewer)" || again.AdminPage != 403 {
		t.Fatalf("alice after the group change: %+v", again)
	}
	if _, n := userNamed(users(t), "alice"); n != 1 {
		t.Fatalf("%d rows for alice after the group change", n)
	}
}

// kcadm runs Keycloak's admin CLI in the container with the bootstrap administrator.
func kcadm(t *testing.T, args string) string {
	t.Helper()
	return sh(t, `. /etc/keycloak.env
export HOME=/tmp
K=/opt/keycloak/bin/kcadm.sh
$K config credentials --server http://127.0.0.1:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null
`+args)
}

func TestOIDCAgainstKeycloak(t *testing.T) {
	idpFresh(t)

	a := drive(t, "oidc", "alice", "alice-test-pw")
	if !a.SignedIn || !strings.HasSuffix(a.CurrentUser, "(admin)") || a.AccountSource != "OpenID Connect" || a.AdminPage != 200 {
		t.Fatalf("alice: %+v", a)
	}
	b := drive(t, "oidc", "bob", "bob-test-pw")
	if !b.SignedIn || !strings.HasSuffix(b.CurrentUser, "(viewer)") || b.AdminPage != 403 {
		t.Fatalf("bob: %+v", b)
	}
	// carol has no groups at all, so Keycloak sends no groups claim (missing, not empty): no role, which
	// is a refusal with the "no role" page and not an error.
	c := drive(t, "oidc", "carol", "carol-test-pw")
	if c.SignedIn || c.Status != 403 || !c.has("error-no-role") {
		t.Fatalf("carol: %+v", c)
	}
	// A wrong password never leaves Keycloak.
	if w := drive(t, "oidc", "alice", "not-the-password"); w.SignedIn || !w.has("keycloak-login-failed") {
		t.Fatalf("wrong password: %+v", w)
	}

	// The identity is issuer + subject.
	us := users(t)
	alice, n := userNamed(us, "alice")
	sub := strings.TrimPrefix(alice.ExternalID, oidcIssuer+" ")
	if n != 1 || alice.AuthSource != "oidc" || !uuidRE.MatchString(sub) || alice.Role != "admin" {
		t.Fatalf("alice: %d rows, %+v", n, alice)
	}
	if _, n := userNamed(us, "carol"); n != 0 {
		t.Fatal("a user in no group was created")
	}

	// The group changes in Keycloak: alice leaves the admin group and joins the viewer group. The next
	// sign-in has the new role, on the same row (M6 decision 20: the role follows the provider at every sign-in).
	kcadm(t, `U=$($K get users -r clamfleet -q username=alice --fields id --format csv --noquotes)
AG=$($K get groups -r clamfleet -q search=`+adminsGroup+` --fields id --format csv --noquotes | head -1)
VG=$($K get groups -r clamfleet -q search=`+viewerGroup+` --fields id --format csv --noquotes | head -1)
$K delete users/$U/groups/$AG -r clamfleet
$K update users/$U/groups/$VG -r clamfleet -s realm=clamfleet -s userId=$U -s groupId=$VG -n`)
	again := drive(t, "oidc", "alice", "alice-test-pw")
	if !again.SignedIn || !strings.HasSuffix(again.CurrentUser, "(viewer)") || again.AdminPage != 403 {
		t.Fatalf("alice after the group change: %+v", again)
	}
	after, n := userNamed(users(t), "alice")
	if n != 1 || after.ExternalID != alice.ExternalID || after.Role != "viewer" {
		t.Fatalf("alice after the group change: %d rows, %+v", n, after)
	}
}
