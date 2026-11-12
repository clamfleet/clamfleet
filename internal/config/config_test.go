// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testPrefix is the agent prefix; the loader takes it as a parameter.
const testPrefix = "CLAMFLEET_AGENT_"

type inner struct {
	Dir string `yaml:"dir"`
	MB  int    `yaml:"max_mb"`
}

type sample struct {
	Server   string        `yaml:"server"`
	Interval time.Duration `yaml:"interval"`
	Tags     []string      `yaml:"tags"`
	Spool    inner         `yaml:"spool"`
}

func defaults() sample {
	return sample{Server: "def", Interval: 5 * time.Minute, Tags: []string{}, Spool: inner{"/d", 50}}
}

func env(m map[string]string) Options {
	return Options{
		EnvPrefix: testPrefix,
		LookupEnv: func(k string) (string, bool) { v, ok := m[k]; return v, ok },
		Environ: func() []string {
			var out []string
			for k, v := range m {
				out = append(out, k+"="+v)
			}
			return out
		},
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsKeptWithoutFileOrEnv(t *testing.T) {
	c := defaults()
	if _, err := Load(&c, env(nil)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, defaults()) {
		t.Fatalf("got %+v", c)
	}
}

func TestFileOverridesDefaultsAndEnvOverridesFile(t *testing.T) {
	c := defaults()
	o := env(map[string]string{"CLAMFLEET_AGENT_SERVER": "from-env", "CLAMFLEET_AGENT_SPOOL_MAX_MB": "7"})
	o.Path = writeFile(t, "server: from-file\ninterval: 10m\ntags: [a, b]\nspool: {dir: /f}\n")
	if _, err := Load(&c, o); err != nil {
		t.Fatal(err)
	}
	want := sample{"from-env", 10 * time.Minute, []string{"a", "b"}, inner{"/f", 7}}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got %+v want %+v", c, want)
	}
}

func TestEnvNamesAreDerivedAndUnique(t *testing.T) {
	c := defaults()
	got := EnvNames(&c, testPrefix)
	want := []string{"CLAMFLEET_AGENT_INTERVAL", "CLAMFLEET_AGENT_SERVER", "CLAMFLEET_AGENT_SPOOL_DIR", "CLAMFLEET_AGENT_SPOOL_MAX_MB", "CLAMFLEET_AGENT_TAGS"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestEnvParseErrorsNameTheVariable(t *testing.T) {
	for _, tc := range []struct{ k, v string }{
		{"CLAMFLEET_AGENT_INTERVAL", "five"},
		{"CLAMFLEET_AGENT_SPOOL_MAX_MB", "x"},
	} {
		c := defaults()
		_, err := Load(&c, env(map[string]string{tc.k: tc.v}))
		if err == nil || !strings.Contains(err.Error(), tc.k) {
			t.Errorf("%s=%s: err = %v, want it to name the variable", tc.k, tc.v, err)
		}
	}
}

func TestEmptyEnvMeansEmptyAndTagsAreTrimmed(t *testing.T) {
	c := defaults()
	c.Server = "x"
	if _, err := Load(&c, env(map[string]string{"CLAMFLEET_AGENT_SERVER": "", "CLAMFLEET_AGENT_TAGS": " a, ,b ,"})); err != nil {
		t.Fatal(err)
	}
	if c.Server != "" || !reflect.DeepEqual(c.Tags, []string{"a", "b"}) {
		t.Fatalf("got %+v", c)
	}
	c = defaults()
	c.Tags = []string{"z"}
	if _, err := Load(&c, env(map[string]string{"CLAMFLEET_AGENT_TAGS": ""})); err != nil {
		t.Fatal(err)
	}
	if c.Tags == nil || len(c.Tags) != 0 {
		t.Fatalf("tags = %#v, want empty non-nil", c.Tags)
	}
}

func TestUnknownYAMLKeyIsAnError(t *testing.T) {
	c := defaults()
	o := env(nil)
	o.Path = writeFile(t, "servr: x\n")
	if _, err := Load(&c, o); err == nil || !strings.Contains(err.Error(), "servr") {
		t.Fatalf("err = %v", err)
	}
}

func TestBareIntegerDurationRejected(t *testing.T) {
	c := defaults()
	o := env(nil)
	o.Path = writeFile(t, "interval: 300\n")
	if _, err := Load(&c, o); err == nil {
		t.Fatal("interval: 300 must be rejected; it would mean 300ns")
	}
}

func TestEmptyAndCommentOnlyFileKeepDefaults(t *testing.T) {
	for _, content := range []string{"", "# nothing\n"} {
		c := defaults()
		o := env(nil)
		o.Path = writeFile(t, content)
		if _, err := Load(&c, o); err != nil || !reflect.DeepEqual(c, defaults()) {
			t.Fatalf("%q: err=%v cfg=%+v", content, err, c)
		}
	}
}

func TestUnknownEnvVarWarnsButConfigVarDoesNot(t *testing.T) {
	c := defaults()
	w, err := Load(&c, env(map[string]string{"CLAMFLEET_AGENT_INTERVALL": "1m", "CLAMFLEET_AGENT_CONFIG": "/x", "OTHER": "1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 1 || !strings.Contains(w[0], "CLAMFLEET_AGENT_INTERVALL") {
		t.Fatalf("warnings = %v", w)
	}
}

// The server will share the host's environment namespace (CLAMFLEET_SERVER_*);
// the agent loader must not call those variables typos, and a different prefix
// must select a different set of names.
func TestOtherPrefixIsNeitherAppliedNorWarned(t *testing.T) {
	c := defaults()
	w, err := Load(&c, env(map[string]string{
		"CLAMFLEET_SERVER_LISTEN": ":8443", "CLAMFLEET_SERVER_CONFIG": "/s", "CLAMFLEET_AGENT_SERVER": "mine",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 0 {
		t.Fatalf("warnings = %v, want none", w)
	}
	if c.Server != "mine" {
		t.Fatalf("server = %q", c.Server)
	}
	o := env(map[string]string{"CLAMFLEET_SERVER_SERVER": "srv", "CLAMFLEET_AGENT_SERVER": "agent"})
	o.EnvPrefix = "CLAMFLEET_SERVER_"
	c = defaults()
	if _, err := Load(&c, o); err != nil || c.Server != "srv" {
		t.Fatalf("server prefix: err=%v server=%q", err, c.Server)
	}
}

// A variable of the other program that matches a key name must not be read as a
// fallback for the agent's own name: the prefix selects the whole name, and
// CLAMFLEET_SERVER_SERVER must not leak into the agent's "server" key.
func TestOtherPrefixKeyNamesAreNotAFallback(t *testing.T) {
	c := defaults()
	c.Tags = []string{"file"}
	w, err := Load(&c, env(map[string]string{
		"CLAMFLEET_SERVER_SERVER": "leak", "CLAMFLEET_SERVER_TAGS": "leak1,leak2",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 0 {
		t.Fatalf("warnings = %v, want none", w)
	}
	if c.Server != "def" || !reflect.DeepEqual(c.Tags, []string{"file"}) {
		t.Fatalf("other prefix leaked into config: %+v", c)
	}
}

func TestResolvePathUsesPrefix(t *testing.T) {
	lookup := func(k string) (string, bool) { return "/p", k == "CLAMFLEET_AGENT_CONFIG" }
	if p, ex := ResolvePath("CLAMFLEET_AGENT_", "", "/def", lookup); p != "/p" || !ex {
		t.Fatalf("got %q %v", p, ex)
	}
	if p, ex := ResolvePath("CLAMFLEET_SERVER_", "", "/def", lookup); p != "/def" || ex {
		t.Fatalf("got %q %v", p, ex)
	}
}

func TestEmptyPrefixIsRejected(t *testing.T) {
	c := defaults()
	if _, err := Load(&c, Options{}); err == nil {
		t.Fatal("an empty prefix would make every variable of the host a config key")
	}
}

func TestMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	c := defaults()
	o := env(nil)
	o.Path = missing
	w, err := Load(&c, o)
	if err != nil || len(w) != 1 {
		t.Fatalf("default path: err=%v warnings=%v", err, w)
	}
	o.Explicit = true
	if _, err := Load(&c, o); err == nil {
		t.Fatal("explicit missing path must be an error")
	}
}

func TestResolvePath(t *testing.T) {
	lk := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	if p, e := ResolvePath(testPrefix, "/flag", "/def", lk(map[string]string{testPrefix + "CONFIG": "/env"})); p != "/flag" || !e {
		t.Fatalf("flag: %s %v", p, e)
	}
	if p, e := ResolvePath(testPrefix, "", "/def", lk(map[string]string{testPrefix + "CONFIG": "/env"})); p != "/env" || !e {
		t.Fatalf("env: %s %v", p, e)
	}
	if p, e := ResolvePath(testPrefix, "", "/def", lk(nil)); p != "/def" || e {
		t.Fatalf("default: %s %v", p, e)
	}
}

func TestUnsupportedFieldTypePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for an unsupported field type")
		}
	}()
	type bad struct {
		F float64 `yaml:"f"`
	}
	EnvNames(&bad{}, testPrefix)
}
