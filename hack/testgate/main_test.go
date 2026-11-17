// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stream builds a `go test -json` stream from "Action|Package|Test|Output" lines, the shape of the
// events the go tool writes (recorded from real runs: a package with no test files, for instance,
// reports an output line and a package-level "skip").
func stream(lines ...string) string {
	var b strings.Builder
	for _, l := range lines {
		f := strings.SplitN(l, "|", 5)
		for len(f) < 5 {
			f = append(f, "")
		}
		b.WriteString(`{"Action":"` + f[0] + `","Package":"` + f[1] + `"`)
		if f[2] != "" {
			b.WriteString(`,"Test":"` + f[2] + `"`)
		}
		if f[3] != "" {
			b.WriteString(`,"Output":"` + f[3] + `"`)
		}
		if f[4] != "" {
			b.WriteString(`,"FailedBuild":"` + f[4] + `"`)
		}
		b.WriteString("}\n")
	}
	return b.String()
}

func gate(t *testing.T, in string, o options) (code int, out, errOut string) {
	t.Helper()
	var so, se bytes.Buffer
	code = run(strings.NewReader(in), &so, &se, o)
	return code, so.String(), se.String()
}

func TestGateVerdicts(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantCode int
		wantErr  string // substring of the findings
	}{
		{"all pass", stream("run|p|TestA", "pass|p|TestA", "pass|p"), 0, "ok, 1 tests passed"},
		{"a failure", stream("pass|p|TestA", "fail|p|TestB", "fail|p"), 1, "test failed: p TestB"},
		{"a failing subtest", stream("pass|p|TestA", "fail|p|TestA/sub", "fail|p|TestA"), 1, "test failed: p TestA/sub"},
		{"a skip", stream("pass|p|TestA", "skip|p|TestB", "pass|p"), 1, "test skipped: p TestB"},
		{"a skipped subtest", stream("pass|p|TestA/x", "skip|p|TestA/y", "pass|p|TestA"), 1, "test skipped: p TestA/y"},
		{"build failure", stream("pass|p|TestA", "fail|q||FAIL\\tq [build failed]\\n|q"), 1, "build failed: q"},
		{"package fail without tests", stream("pass|p|TestA", "fail|q"), 1, "package failed: q"},
		{"empty stream", "", 1, "no test passed"},
		{"only a package without tests", stream("output|p||?   \\tp\\t[no test files]\\n", "skip|p"), 1, "no test passed"},
		// A package with no test files reports a package-level skip. It must not count as a skipped test.
		{"no-test package next to passing ones", stream("skip|q", "pass|p|TestA", "pass|p"), 0, "ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := gate(t, c.in, options{})
			if code != c.wantCode || !strings.Contains(errOut, c.wantErr) {
				t.Fatalf("code %d (want %d), findings:\n%s\nwant substring %q", code, c.wantCode, errOut, c.wantErr)
			}
		})
	}
}

func TestGateBuildFailEvent(t *testing.T) {
	in := `{"ImportPath":"p [p.test]","Action":"build-output","Output":"x.go:3: undefined: y\n"}` + "\n" +
		`{"ImportPath":"p [p.test]","Action":"build-fail"}` + "\n" +
		stream("pass|q|TestA")
	code, out, errOut := gate(t, in, options{})
	if code != 1 || !strings.Contains(errOut, "build failed: p [p.test]") {
		t.Fatalf("code %d, findings:\n%s", code, errOut)
	}
	if !strings.Contains(out, "undefined: y") {
		t.Fatalf("the compiler output must reach the log, got %q", out)
	}
}

// The test output is printed as plain text, and a line that is not an event (go's own
// "go: downloading" notes) is shown too and is never evidence of a pass.
func TestGatePrintsOutput(t *testing.T) {
	in := "go: downloading example.test/m v1.0.0\n" +
		stream("output|p|TestA|=== RUN   TestA\\n", "output|p|TestA|--- PASS: TestA\\n", "pass|p|TestA")
	code, out, _ := gate(t, in, options{})
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{"go: downloading example.test/m", "=== RUN   TestA\n", "--- PASS: TestA\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if code, _, _ := gate(t, "go: downloading x\nnot json at all\n", options{}); code != 1 {
		t.Errorf("a stream of plain text must not pass, got %d", code)
	}
}

// writeModule makes a temporary module whose package "e" mirrors the e2e package: a TestMain, a
// file selected only by the "e2e" tag, a file selected only by "e2e && other", an external test
// package, and things that look like tests but are not.
func writeModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.test/m\n\ngo 1.21\n",
		"e/a_test.go": `//go:build e2e

package e

import "testing"

func TestMain(m *testing.M) { m.Run() }
func TestOne(t *testing.T)  {}
func TestTwo(t *testing.T)  { t.Run("sub", func(t *testing.T) {}) }
func Testlower(t *testing.T) {}
func TestWrongArg(t *testing.M) {}
func helperTest(t *testing.T)  {}
type S struct{}
func (S) TestMethod(t *testing.T) {}
`,
		"e/b_test.go": `//go:build e2e && other

package e

import "testing"

func TestOther(t *testing.T) {}
`,
		"e/x_test.go": `//go:build e2e

package e_test

import "testing"

func TestExternal(t *testing.T) {}
`,
		"e/lib.go": "package e\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestGateExpectPkg(t *testing.T) {
	dir := writeModule(t)
	o := options{expectPkg: "./e", tags: "e2e", goBin: "go", dir: dir}
	const p = "example.test/m/e"
	good := stream("pass|"+p+"|TestOne", "pass|"+p+"|TestTwo/sub", "pass|"+p+"|TestTwo", "pass|"+p+"|TestExternal", "pass|"+p)

	if code, _, errOut := gate(t, good, o); code != 0 {
		t.Fatalf("the declared set passed, got %d:\n%s", code, errOut)
	}
	// Tests counted twice (-count=2) are one test.
	if code, _, errOut := gate(t, good+good, o); code != 0 {
		t.Fatalf("a repeated run must still pass, got %d:\n%s", code, errOut)
	}

	cases := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"a test never ran (narrowed -run)", stream("pass|"+p+"|TestOne", "pass|"+p), "did not pass"},
		{"a missing external test", stream("pass|"+p+"|TestOne", "pass|"+p+"|TestTwo"), "TestExternal"},
		{"subtests do not stand in for their parent", stream("pass|"+p+"|TestOne", "pass|"+p+"|TestTwo/sub", "pass|"+p+"|TestExternal"), "TestTwo"},
		// TestOther sits behind "e2e && other": only the tag set given to the go tool decides.
		{"a test of a file the tags exclude", stream("pass|"+p+"|TestOne", "pass|"+p+"|TestTwo", "pass|"+p+"|TestExternal", "pass|"+p+"|TestOther"), "does not declare: TestOther"},
		{"a typo", stream("pass|"+p+"|TestOne", "pass|"+p+"|TestTwo", "pass|"+p+"|TestExternal", "pass|"+p+"|TestTwoo"), "TestTwoo"},
		{"only another package passed", stream("pass|other|TestOne", "pass|other|TestTwo", "pass|other|TestExternal"), "did not pass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := gate(t, c.in, o)
			if code != 1 || !strings.Contains(errOut, c.wantErr) {
				t.Fatalf("code %d, findings:\n%s\nwant substring %q", code, errOut, c.wantErr)
			}
		})
	}

	t.Run("the other tag set expects the other file", func(t *testing.T) {
		o2 := o
		o2.tags = "e2e other"
		code, _, errOut := gate(t, good, o2)
		if code != 1 || !strings.Contains(errOut, "TestOther") {
			t.Fatalf("code %d:\n%s", code, errOut)
		}
	})
	t.Run("lookalikes are not tests", func(t *testing.T) {
		_, names, err := declaredTests(o)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"TestMain", "Testlower", "TestWrongArg", "helperTest", "TestMethod", "TestOther"} {
			if names[bad] {
				t.Errorf("%s must not be expected", bad)
			}
		}
		if len(names) != 3 {
			t.Errorf("want TestOne, TestTwo, TestExternal, got %v", names)
		}
	})
	t.Run("a package without tests under the tags is an error, not a pass", func(t *testing.T) {
		o3 := o
		o3.tags = ""
		code, _, errOut := gate(t, good, o3)
		if code != 2 || !strings.Contains(errOut, "declares no tests") {
			t.Fatalf("code %d:\n%s", code, errOut)
		}
	})
	t.Run("go list failure", func(t *testing.T) {
		o4 := o
		o4.expectPkg = "./nope"
		if code, _, _ := gate(t, good, o4); code != 2 {
			t.Fatalf("code %d, want 2", code)
		}
	})
}
