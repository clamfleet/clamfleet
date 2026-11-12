// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// env.go: environment-variable overrides for the config loader.
//
// Responsibilities: derive one variable name per config key from the yaml tags
// (the caller's prefix + the tag path, upper-cased), apply the variables that are set,
// and warn about variables with the prefix that match no key.
// Dependencies: reflect and the standard library only; works on any config
// struct, so the server can reuse it.

package config

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

var durationType = reflect.TypeOf(time.Duration(0))

// leaf is one settable config value found by walking the struct.
type leaf struct {
	env string
	val reflect.Value
}

// walk lists every leaf of the struct behind ptr, naming each by its yaml
// tags: prefix + the tag path upper-cased, joined by "_". Deriving the
// names from the tags (instead of a hand-kept table) means a new key gets an
// env name automatically. A field of a kind the loader cannot parse panics,
// so a new key of an unsupported type is caught by the test suite and never
// reaches production.
func walk(ptr any, prefix string) []leaf {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		panic("config: Load needs a pointer to a struct")
	}
	var out []leaf
	var rec func(prefix string, v reflect.Value)
	rec = func(prefix string, v reflect.Value) {
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" {
				panic(fmt.Sprintf("config: field %s has no yaml tag", f.Name))
			}
			env := prefix + strings.ToUpper(name)
			fv := v.Field(i)
			switch {
			case f.Type == durationType, f.Type.Kind() == reflect.String,
				f.Type.Kind() == reflect.Int, f.Type.Kind() == reflect.Bool,
				f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.String:
				out = append(out, leaf{env, fv})
			case f.Type.Kind() == reflect.Struct:
				rec(env+"_", fv)
			default:
				panic(fmt.Sprintf("config: unsupported field type %s for %s", f.Type, env))
			}
		}
	}
	rec(prefix, v.Elem())
	return out
}

// EnvNames returns every environment variable name the struct accepts, sorted.
func EnvNames(ptr any, prefix string) []string {
	var names []string
	for _, l := range walk(ptr, prefix) {
		names = append(names, l.env)
	}
	sort.Strings(names)
	return names
}

// applyEnv sets each leaf whose variable is present. Presence, not value,
// decides: a variable that is set but empty clears the value (an operator may
// want to empty "tags"). Only variables with the given prefix are looked at, so
// another program's variables (CLAMFLEET_SERVER_* next to the agent's) never warn. Those that match no key are
// returned as warnings, which catches typos like CLAMFLEET_AGENT_INTERVALL.
func applyEnv(ptr any, prefix string, lookup func(string) (string, bool), environ func() []string) ([]string, error) {
	known := map[string]bool{prefix + envConfigSuffix: true}
	for _, l := range walk(ptr, prefix) {
		known[l.env] = true
		raw, ok := lookup(l.env)
		if !ok {
			continue
		}
		if err := setValue(l.val, raw); err != nil {
			return nil, fmt.Errorf("%s: %w", l.env, err)
		}
	}
	var warnings []string
	for _, kv := range environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, prefix) && !known[name] {
			warnings = append(warnings, fmt.Sprintf("unknown environment variable %s ignored", name))
		}
	}
	sort.Strings(warnings)
	return warnings, nil
}

func setValue(v reflect.Value, raw string) error {
	switch {
	case v.Type() == durationType:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("invalid duration %q (use e.g. 5m)", raw)
		}
		v.SetInt(int64(d))
	case v.Kind() == reflect.String:
		v.SetString(raw)
	case v.Kind() == reflect.Int:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("invalid integer %q", raw)
		}
		v.SetInt(int64(n))
	case v.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("invalid boolean %q", raw)
		}
		v.SetBool(b)
	case v.Kind() == reflect.Slice:
		// Comma-separated, items trimmed, empty items dropped.
		list := []string{}
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, p)
			}
		}
		v.Set(reflect.ValueOf(list))
	}
	return nil
}
