// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agentauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	tok, hash, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 47 || !strings.HasPrefix(tok, "cfa_") {
		t.Fatalf("token %q: want cfa_ + 43 characters", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok[4:])
	if err != nil || len(raw) != 32 {
		t.Fatalf("secret does not decode to 32 bytes: %v len=%d", err, len(raw))
	}
	if want := sha256.Sum256([]byte(tok)); !bytes.Equal(hash, want[:]) {
		t.Fatal("hash is not SHA-256 of the whole token string")
	}
	if err := Parse(tok); err != nil {
		t.Fatalf("a generated token must parse: %v", err)
	}
	tok2, _, _ := Generate()
	if tok == tok2 {
		t.Fatal("two tokens are equal")
	}
}

func TestHashIsSHA256OfWholeString(t *testing.T) {
	want := sha256.Sum256([]byte("cfa_x"))
	if !bytes.Equal(Hash("cfa_x"), want[:]) {
		t.Fatal("Hash != sha256")
	}
}

func TestParseRejects(t *testing.T) {
	good, _, _ := Generate()
	body := good[4:]
	cases := map[string]string{
		"empty":           "",
		"wrong prefix":    "cfb_" + body,
		"user token":      "cfu_" + body,
		"no prefix":       body,
		"short":           good[:46],
		"long":            good + "A",
		"padding":         good[:46] + "=",
		"plus":            "cfa_" + strings.Replace(body, body[:1], "+", 1),
		"slash":           "cfa_" + "/" + body[1:],
		"space":           "cfa_ " + body[1:],
		"trailing space":  good + " ",
		"newline":         good[:46] + "\n",
		"upper prefix":    "CFA_" + body,
		"nonzero trailer": "cfa_" + body[:42] + "B", // a last char whose spare bits are not zero is a second spelling of another secret
	}
	for name, tok := range cases {
		if err := Parse(tok); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Parse(%q) = %v, want ErrMalformed", name, tok, err)
		}
	}
	for name, tok := range cases {
		if err := Parse(tok); err != nil && strings.Contains(err.Error(), tok) && tok != "" {
			t.Errorf("%s: error text contains the input", name)
		}
	}
}

// countingLookup records calls so a test can prove the store was (not) asked.
type countingLookup struct {
	calls int
	id    Identity
	err   error
}

func (c *countingLookup) lookup(_ context.Context, _ []byte) (Identity, error) {
	c.calls++
	return c.id, c.err
}

func reqWith(h string) *http.Request {
	r := httptest.NewRequest("POST", "/v1/report", nil)
	if h != "" {
		r.Header.Set("Authorization", h)
	}
	return r
}

func TestBearerHeaderParsing(t *testing.T) {
	tok, _, _ := Generate()
	ok := Identity{HostID: 7, HostName: "a"}
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{"plain", "Bearer " + tok, true},
		{"lower scheme", "bearer " + tok, true},
		{"upper scheme", "BEARER " + tok, true},
		{"extra spaces before token", "Bearer    " + tok, true},
		{"basic", "Basic " + tok, false},
		{"no scheme", tok, false},
		{"scheme only", "Bearer", false},
		{"scheme and space", "Bearer ", false},
		{"empty", "", false},
		{"trailing space", "Bearer " + tok + " ", false},
		{"two tokens", "Bearer " + tok + " " + tok, false},
	}
	for _, c := range cases {
		lk := &countingLookup{id: ok}
		id, err := Bearer{Lookup: lk.lookup}.Authenticate(reqWith(c.header))
		if c.want && (err != nil || id != ok) {
			t.Errorf("%s: got %+v, %v", c.name, id, err)
		}
		if !c.want && !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", c.name, err)
		}
		if !c.want && lk.calls != 0 {
			t.Errorf("%s: lookup called %d times for a bad header", c.name, lk.calls)
		}
	}
}

func TestTwoAuthorizationHeadersRejected(t *testing.T) {
	tok, _, _ := Generate()
	r := reqWith("Bearer " + tok)
	r.Header.Add("Authorization", "Bearer "+tok)
	lk := &countingLookup{}
	if _, err := (Bearer{Lookup: lk.lookup}).Authenticate(r); !errors.Is(err, ErrUnauthenticated) || lk.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, lk.calls)
	}
}

func TestLookupNotCalledForMalformedTokens(t *testing.T) {
	good, _, _ := Generate()
	for _, h := range []string{
		"Bearer cfa_short", "Bearer cfu_" + good[4:], "Bearer " + good[:46] + "=", "Bearer " + strings.Repeat("x", 5000),
	} {
		lk := &countingLookup{}
		_, err := Bearer{Lookup: lk.lookup}.Authenticate(reqWith(h))
		if !errors.Is(err, ErrUnauthenticated) || lk.calls != 0 {
			t.Errorf("%.20s...: err=%v lookups=%d", h, err, lk.calls)
		}
	}
}

func TestLookupReceivesHashNotToken(t *testing.T) {
	tok, want, _ := Generate()
	var got []byte
	b := Bearer{Lookup: func(_ context.Context, h []byte) (Identity, error) { got = h; return Identity{HostID: 1}, nil }}
	if _, err := b.Authenticate(reqWith("Bearer " + tok)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("lookup must get SHA-256(token)")
	}
}

func TestUnknownIsUnauthenticatedStoreErrorIsUnavailable(t *testing.T) {
	tok, _, _ := Generate()
	h := "Bearer " + tok
	lk := &countingLookup{err: ErrUnknownToken}
	if _, err := (Bearer{Lookup: lk.lookup}).Authenticate(reqWith(h)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unknown token: %v", err)
	}
	lk = &countingLookup{err: errors.New("database is locked")}
	_, err := Bearer{Lookup: lk.lookup}.Authenticate(reqWith(h))
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("store error: %v, want ErrUnavailable and not ErrUnauthenticated", err)
	}
}

type fixed struct {
	id  Identity
	err error
}

func (f fixed) Authenticate(*http.Request) (Identity, error) { return f.id, f.err }

func TestMiddleware(t *testing.T) {
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := FromContext(r.Context())
		if !ok || id.HostName != "a" {
			t.Errorf("identity missing in context: %+v %v", id, ok)
		}
		w.WriteHeader(http.StatusAccepted)
	})
	cases := []struct {
		name   string
		a      Authenticator
		status int
		www    string
	}{
		{"ok", fixed{id: Identity{HostID: 1, HostName: "a"}}, 202, ""},
		{"unauthenticated", fixed{err: ErrUnauthenticated}, 401, `Bearer realm="clamfleet"`},
		{"unavailable", fixed{err: ErrUnavailable}, 503, ""},
		{"other error is not a 401", fixed{err: errors.New("boom")}, 503, ""},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		Middleware(c.a, log)(next).ServeHTTP(rec, reqWith(""))
		if rec.Code != c.status || rec.Header().Get("WWW-Authenticate") != c.www {
			t.Errorf("%s: %d %q", c.name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
		if c.status != 202 && rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: content type %q", c.name, rec.Header().Get("Content-Type"))
		}
	}
}

func TestFromContextEmpty(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("empty context must have no identity")
	}
}
