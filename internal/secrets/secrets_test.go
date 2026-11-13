// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newRing(t *testing.T, n int) (*Keyring, [][]byte) {
	t.Helper()
	var text string
	var keys [][]byte
	for i := 0; i < n; i++ {
		k, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
		text += EncodeKeyLine(k)
	}
	r, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return r, keys
}

func TestSealOpenRoundTrip(t *testing.T) {
	r, _ := newRing(t, 1)
	pt := []byte("12345678901234567890")
	blob, err := r.Seal("totp", pt, 7)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, pt) {
		t.Fatal("the plaintext is visible in the blob")
	}
	got, err := r.Open("totp", blob, 7)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip: %v %q", err, got)
	}
	blob2, _ := r.Seal("totp", pt, 7)
	if bytes.Equal(blob, blob2) {
		t.Fatal("two seals of one plaintext are identical: the nonce is not random")
	}
}

// Rule: a blob is bound to its purpose and to its row ids.
func TestOpenRefusesWrongPurposeOrRow(t *testing.T) {
	r, _ := newRing(t, 1)
	blob, _ := r.Seal("totp", []byte("secret"), 7)
	for name, f := range map[string]func() error{
		"another purpose":   func() error { _, err := r.Open("totp-pending", blob, 7); return err },
		"another user id":   func() error { _, err := r.Open("totp", blob, 8); return err },
		"an extra id":       func() error { _, err := r.Open("totp", blob, 7, 1); return err },
		"no id":             func() error { _, err := r.Open("totp", blob); return err },
		"a webhook purpose": func() error { _, err := r.Open("webhook", blob, 7); return err },
	} {
		if err := f(); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: %v, want ErrDecrypt", name, err)
		}
	}
}

func TestOpenRefusesAnyFlippedByte(t *testing.T) {
	r, _ := newRing(t, 1)
	blob, _ := r.Seal("totp", []byte("secret"), 7)
	for i := range blob {
		bad := append([]byte(nil), blob...)
		bad[i] ^= 0x01
		_, err := r.Open("totp", bad, 7)
		if err == nil {
			t.Fatalf("byte %d flipped, still opens", i)
		}
		if i >= 1 && i < 9 && !errors.Is(err, ErrUnknownKey) { // inside the key id
			t.Errorf("byte %d: %v, want ErrUnknownKey", i, err)
		}
	}
	if _, err := r.Open("totp", blob[:10], 7); !errors.Is(err, ErrDecrypt) {
		t.Errorf("truncated blob: %v", err)
	}
	if _, err := r.Open("totp", nil, 7); !errors.Is(err, ErrDecrypt) {
		t.Errorf("nil blob: %v", err)
	}
}

func TestUnknownKey(t *testing.T) {
	a, _ := newRing(t, 1)
	b, _ := newRing(t, 1)
	blob, _ := a.Seal("totp", []byte("secret"), 1)
	if _, err := b.Open("totp", blob, 1); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("%v, want ErrUnknownKey", err)
	}
}

// Rotation: the first key seals, every key opens, NeedsReseal says which blobs are old.
func TestRotationRing(t *testing.T) {
	old, keys := newRing(t, 1)
	oldBlob, _ := old.Seal("totp", []byte("secret"), 1)

	fresh, _ := GenerateKey()
	rotated, err := Parse(strings.NewReader(EncodeKeyLine(fresh) + EncodeKeyLine(keys[0])))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ActiveID() != KeyID(fresh) {
		t.Fatal("the first key of the file is not the active one")
	}
	if got, err := rotated.Open("totp", oldBlob, 1); err != nil || string(got) != "secret" {
		t.Fatalf("the old key no longer opens old blobs: %v", err)
	}
	if !rotated.NeedsReseal(oldBlob) {
		t.Error("a blob of the old key must need re-sealing")
	}
	newBlob, _ := rotated.Seal("totp", []byte("secret"), 1)
	if rotated.NeedsReseal(newBlob) {
		t.Error("a blob of the active key must not need re-sealing")
	}
	if rotated.NeedsReseal([]byte{1, 2}) || rotated.NeedsReseal(nil) {
		t.Error("a malformed blob is not 'needs reseal': Open reports it")
	}
	if _, err := old.Open("totp", newBlob, 1); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("the old ring must not open a blob of the new key: %v", err)
	}
}

func TestParse(t *testing.T) {
	k, _ := GenerateKey()
	line := base64.StdEncoding.EncodeToString(k)
	for name, c := range map[string]struct {
		in string
		ok bool
	}{
		"comments and blank lines": {"# a comment\n\n   \n" + line + "\n# more\n", true},
		"no trailing newline":      {line, true},
		"crlf":                     {line + "\r\n", true},
		"empty file":               {"", false},
		"only comments":            {"# nothing\n", false},
		"bad base64":               {"not base64!!\n", false},
		"31 bytes":                 {base64.StdEncoding.EncodeToString(k[:31]) + "\n", false},
		"33 bytes":                 {base64.StdEncoding.EncodeToString(append(append([]byte(nil), k...), 0)) + "\n", false},
		"duplicate key":            {line + "\n" + line + "\n", false},
	} {
		_, err := Parse(strings.NewReader(c.in))
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, c.ok)
		}
		if err != nil && strings.Contains(err.Error(), line) {
			t.Errorf("%s: the error repeats the key", name)
		}
	}
}

func writeKey(t *testing.T, mode os.FileMode) string {
	t.Helper()
	k, _ := GenerateKey()
	p := filepath.Join(t.TempDir(), "k.key")
	if err := os.WriteFile(p, []byte(EncodeKeyLine(k)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // chmod, not WriteFile's mode: the umask would mask 0606
		t.Fatal(err)
	}
	return p
}

func TestLoadFilePermissions(t *testing.T) {
	for mode, ok := range map[os.FileMode]bool{
		0o600: true, 0o640: true, 0o400: true,
		0o644: false, 0o660: false, 0o606: false, 0o604: false, 0o620: false, 0o666: false,
	} {
		_, err := LoadFile(writeKey(t, mode))
		if (err == nil) != ok {
			t.Errorf("mode %04o: err=%v, want ok=%v", mode, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "must not be readable by others") {
			t.Errorf("mode %04o: unhelpful error %q", mode, err)
		}
	}
}

func TestLoadFileRefusesASymlinkAndANonFile(t *testing.T) {
	real := writeKey(t, 0o600)
	link := filepath.Join(t.TempDir(), "link.key")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("symlink: %v", err)
	}
	if _, err := LoadFile(t.TempDir()); err == nil {
		t.Error("a directory was accepted")
	}
}

// "Absent" and "present but wrong" are different outcomes for the server's start-up.
func TestLoadFileMissingIsDistinguishable(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "none.key"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%v: want an error that is os.ErrNotExist", err)
	}
	empty := filepath.Join(t.TempDir(), "e.key")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(empty); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Errorf("an empty file must be an invalid file, not an absent one: %v", err)
	}
}

func TestLoadFileOK(t *testing.T) {
	r, err := LoadFile(writeKey(t, 0o640))
	if err != nil || r.Len() != 1 {
		t.Fatalf("%v", err)
	}
}

func TestErrorsLeakNothing(t *testing.T) {
	r, keys := newRing(t, 1)
	pt := []byte("super-secret-plaintext")
	blob, _ := r.Seal("totp", pt, 1)
	_, err := r.Open("totp", blob, 2)
	for _, s := range []string{base64.StdEncoding.EncodeToString(keys[0]), string(pt)} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error %q leaks %q", err, s)
		}
	}
}

// The alert-target purpose seals with the target id as AAD: a blob copied to
// another target's row does not open (mutation 33: AAD without the id).
func TestAlertTargetPurposeRoundTripAndRowBinding(t *testing.T) {
	r, _ := newRing(t, 1)
	blob, err := r.Seal(PurposeAlertTarget, []byte(`{"url":"https://hooks.example/T","signing_key":"whsec_x"}`), 7)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Open(PurposeAlertTarget, blob, 7); err != nil || !strings.Contains(string(got), "hooks.example") {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := r.Open(PurposeAlertTarget, blob, 8); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another target id: %v", err)
	}
	if _, err := r.Open(PurposeTOTP, blob, 7); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another purpose: %v", err)
	}
	if bytes.Contains(blob, []byte("hooks.example")) {
		t.Fatal("the URL is in the blob in clear")
	}
}

func writeSecretFile(t *testing.T, mode os.FileMode, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // umask must not weaken the test
		t.Fatal(err)
	}
	return p
}

func TestReadProtectedFilePermissions(t *testing.T) {
	for mode, ok := range map[os.FileMode]bool{0o600: true, 0o640: true, 0o644: false, 0o660: false, 0o666: false} {
		got, err := ReadProtectedFile(writeSecretFile(t, mode, "hunter2\n"), "smtp.password_file")
		if (err == nil) != ok {
			t.Errorf("mode %04o: err=%v, want ok=%v", mode, err, ok)
		}
		if err == nil && got != "hunter2" {
			t.Errorf("mode %04o: got %q, the trailing newline must be trimmed", mode, got)
		}
		if err != nil && (!strings.Contains(err.Error(), "smtp.password_file") || strings.Contains(err.Error(), "hunter2")) {
			t.Errorf("mode %04o: error %q", mode, err)
		}
	}
}

func TestReadProtectedFileRefusesSymlinkMissingAndEmpty(t *testing.T) {
	real := writeSecretFile(t, 0o600, "x")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedFile(link, "f"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("symlink: %v", err)
	}
	if _, err := ReadProtectedFile(filepath.Join(t.TempDir(), "none"), "f"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, err := ReadProtectedFile(writeSecretFile(t, 0o600, " \n"), "f"); err == nil {
		t.Error("an empty file was accepted")
	}
}
