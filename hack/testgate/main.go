// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command testgate is the pass/fail gate CI puts behind `go test -json`: it prints the test
// output as plain text and exits 1 unless every test passed AND none was skipped.
//
//	go test -count=1 -json ./... | testgate
//	go test -tags e2e -count=1 -json ./e2e | testgate -expect-pkg ./e2e -tags e2e
//
// Why it exists. `go test` exits 0 for a test that calls t.Skip, and a skipped test is how an
// outage turns into a pass (CLAUDE.md, testing policy: a test that skips itself at runtime cannot
// fail when the feature breaks). The gate makes every skip a failure. There is deliberately NO
// allowlist: a test that cannot run in CI is excluded by a build tag in a reviewed change, never by
// a runtime skip.
//
// What it fails on:
//   - any test or package with the action "fail";
//   - any test, or subtest, with the action "skip" (a package with no test files also reports
//     "skip", but without a test name: that is not a finding);
//   - a package that failed to build (the "FailedBuild" field, or a "build-fail" event);
//   - input in which no test passed at all (an empty stream means `go test` died before running);
//   - with -expect-pkg: any difference between the top-level tests that passed in that package and
//     the top-level tests its files declare. That catches a narrowed -run, a test that never ran
//     and a typo in a filter. Build constraints are evaluated by the go tool (`go list -tags ...`),
//     never by a regexp, and the files are parsed with go/parser. Subtests are ignored, and so is
//     TestMain, which is not a test.
//   - with -expect-run REGEXP (needs -expect-pkg): the same comparison, but the declared set is first
//     narrowed to the top-level tests REGEXP matches. It is the pattern the caller also gives to
//     `go test -run`, so a deliberately narrowed run (a VM suite that runs a few tests of a package)
//     still fails when one of them did not run. A pattern that selects no declared test is a failure,
//     so a typo cannot pass, and a pattern with an unbracketed "/" is refused (see checkRunPattern).
//
// The stream is read to the end even after the first problem, so the log shows every failure.
// Test output goes to stdout unchanged; the gate's own findings go to stderr.
//
// Dependencies: the standard library and the `go` command (only for -expect-pkg).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// event is one line of `go test -json` (the test2json format plus the build events of Go 1.24+).
// Only the fields the gate reads are declared.
type event struct {
	Action      string
	Package     string
	ImportPath  string // build-output and build-fail events name the package here
	Test        string
	Output      string
	FailedBuild string
}

// options are the command line of the gate.
type options struct {
	expectPkg string // package whose declared top-level tests must all pass, "" for no check
	expectRun string // regexp the same `go test -run` gets: narrows the declared set, "" for no narrowing
	tags      string // build tags for the `go list` of expectPkg
	goBin     string // the go command, replaceable in tests
	dir       string // working directory of `go list`, "" for the current one
}

func main() {
	var o options
	flag.StringVar(&o.expectPkg, "expect-pkg", "", "package (as `go list` takes it) whose declared top-level tests must equal the set that passed")
	flag.StringVar(&o.expectRun, "expect-run", "", "regexp given to `go test -run`: only the declared top-level tests it matches are expected (needs -expect-pkg)")
	flag.StringVar(&o.tags, "tags", "", "build tags for -expect-pkg, as for `go test -tags`")
	flag.StringVar(&o.goBin, "go", "go", "the go command")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: go test -json ... | testgate [-expect-pkg PKG [-tags TAGS] [-expect-run REGEXP]]")
		os.Exit(2)
	}
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, o))
}

// run reads the stream, prints the output and findings, and returns the process exit code:
// 0 all good, 1 a finding, 2 the gate itself could not do its job (unreadable input, or go list failed).
// It reads from in and writes to out and errw only, so tests can drive it with recorded streams.
func run(in io.Reader, out, errw io.Writer, o options) int {
	// Checked before reading anything: a gate that is mis-called must not look like a verdict on the tests.
	var runRE *regexp.Regexp
	if o.expectRun != "" {
		if o.expectPkg == "" {
			fmt.Fprintln(errw, "testgate: -expect-run needs -expect-pkg: there is no declared set to narrow")
			return 2
		}
		var err error
		if runRE, err = compileRunPattern(o.expectRun); err != nil {
			fmt.Fprintln(errw, "testgate:", err)
			return 2
		}
	}
	var (
		passed   = map[string]bool{} // "pkg\x00Test" of top-level tests that passed, for expect-pkg
		nPass    int
		failures []string
		skips    []string
	)
	br := bufio.NewReader(in)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var ev event
			if jerr := json.Unmarshal(line, &ev); jerr != nil {
				// Not an event: `go: downloading ...`, or a build error from a go command that does
				// not emit JSON for it. Show it; it is never evidence of a pass.
				out.Write(line)
			} else {
				switch ev.Action {
				case "output", "build-output":
					io.WriteString(out, ev.Output)
				case "build-fail":
					failures = append(failures, "build failed: "+ev.ImportPath)
				case "fail":
					switch {
					case ev.FailedBuild != "":
						failures = append(failures, "build failed: "+ev.Package+" (does not compile: "+ev.FailedBuild+")")
					case ev.Test == "":
						failures = append(failures, "package failed: "+ev.Package)
					default:
						failures = append(failures, "test failed: "+ev.Package+" "+ev.Test)
					}
				case "skip":
					if ev.Test != "" {
						skips = append(skips, ev.Package+" "+ev.Test)
					}
				case "pass":
					if ev.Test != "" {
						nPass++
						if !strings.Contains(ev.Test, "/") {
							passed[ev.Package+"\x00"+ev.Test] = true
						}
					}
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Fprintln(errw, "testgate: reading input:", err)
				return 2
			}
			break
		}
	}

	var problems []string
	problems = append(problems, failures...)
	for _, s := range skips {
		problems = append(problems, "test skipped: "+s+" (a skip is a failure here: exclude a test from CI with a build tag, in a reviewed change)")
	}
	if nPass == 0 && len(failures) == 0 {
		problems = append(problems, "no test passed (an empty or truncated stream: did `go test` run?)")
	}
	if o.expectPkg != "" {
		pkg, want, err := declaredTests(o)
		if err != nil {
			fmt.Fprintln(errw, "testgate:", err)
			return 2
		}
		declared := want
		if runRE != nil {
			// regexp.MatchString semantics (unanchored), as go test -run applies it to a top-level name.
			want = map[string]bool{}
			for name := range declared {
				if runRE.MatchString(name) {
					want[name] = true
				}
			}
			if len(want) == 0 {
				fmt.Fprintf(errw, "testgate: -expect-run %q matches none of the %d tests %s declares (a typo, or wrong -tags)\n", o.expectRun, len(declared), pkg)
				return 1
			}
		}
		var missing, extra []string
		for name := range want {
			if !passed[pkg+"\x00"+name] {
				missing = append(missing, name)
			}
		}
		for k := range passed {
			p, name, _ := strings.Cut(k, "\x00")
			if p == pkg && !declared[name] {
				extra = append(extra, name)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("%d of the %d tests %s declares did not pass (never ran, or narrowed by -run?): %s",
				len(missing), len(want), pkg, strings.Join(missing, ", ")))
		}
		if len(extra) > 0 {
			problems = append(problems, fmt.Sprintf("tests passed that %s does not declare: %s", pkg, strings.Join(extra, ", ")))
		}
		if len(missing) == 0 && len(extra) == 0 {
			fmt.Fprintf(errw, "testgate: all %d expected top-level tests of %s passed\n", len(want), pkg)
		}
	}

	if len(problems) == 0 {
		fmt.Fprintf(errw, "testgate: ok, %d tests passed, none failed or skipped\n", nPass)
		return 0
	}
	fmt.Fprintf(errw, "testgate: FAIL, %d problem(s):\n", len(problems))
	for _, p := range problems {
		fmt.Fprintln(errw, "  "+p)
	}
	return 1
}

// compileRunPattern compiles the -expect-run pattern. `go test -run` splits its pattern at every "/"
// outside brackets and matches the first element against top-level names and the rest against
// subtests. The gate only compares top-level names, so it refuses such a pattern: it would silently
// disagree with go about what was selected. A "/" inside [...] is not a separator for go either.
func compileRunPattern(pat string) (*regexp.Regexp, error) {
	inClass := false
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '\\':
			i++ // an escaped character is never a separator or a bracket
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				return nil, fmt.Errorf("-expect-run %q contains an unbracketed \"/\": go test -run would split it into per-subtest patterns, which the gate does not model", pat)
			}
		}
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, fmt.Errorf("-expect-run %q: %w", pat, err)
	}
	return re, nil
}

// declaredTests returns the import path of o.expectPkg and the names of the top-level tests that
// the go tool selects for it under o.tags. Both the in-package and the external (_test package)
// test files count.
func declaredTests(o options) (importPath string, names map[string]bool, err error) {
	args := []string{"list"}
	if o.tags != "" {
		args = append(args, "-tags", o.tags)
	}
	args = append(args, "-json", o.expectPkg)
	cmd := exec.Command(o.goBin, args...)
	cmd.Dir = o.dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		return "", nil, fmt.Errorf("go list %s: %w: %s", o.expectPkg, err, strings.TrimSpace(stderr.String()))
	}
	var pkg struct {
		Dir          string
		ImportPath   string
		TestGoFiles  []string
		XTestGoFiles []string
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return "", nil, fmt.Errorf("go list %s: %w", o.expectPkg, err)
	}
	names = map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range append(append([]string{}, pkg.TestGoFiles...), pkg.XTestGoFiles...) {
		file, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, f), nil, 0)
		if err != nil {
			return "", nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && isTest(fn) {
				names[fn.Name.Name] = true
			}
		}
	}
	if len(names) == 0 {
		return "", nil, fmt.Errorf("%s declares no tests under tags %q: wrong -expect-pkg or -tags", o.expectPkg, o.tags)
	}
	return pkg.ImportPath, names, nil
}

// isTest reports whether fn is a test the go tool would run: a top-level function named Test
// followed by something that is not a lower-case letter, taking exactly one *testing.T.
// TestMain takes *testing.M and is therefore not a test.
func isTest(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
		return false
	}
	if rest := fn.Name.Name[len("Test"):]; rest != "" {
		if r, _ := utf8.DecodeRuneInString(rest); unicode.IsLower(r) {
			return false
		}
	}
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) > 1 {
		return false
	}
	star, ok := params[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "T"
}
