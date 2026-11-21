// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRecipients(t *testing.T) {
	got, err := ParseRecipients("A@x.example, b@x.example;\n a@X.example  <c@x.example>")
	if err != nil || !reflect.DeepEqual(got, []string{"A@x.example", "b@x.example", "c@x.example"}) {
		t.Fatalf("%v %v (duplicates compare case-insensitively)", got, err)
	}
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, "u"+strings.Repeat("a", i)+"@x.example")
	}
	for name, in := range map[string]string{"empty": " ,; ", "invalid": "nope", "21": strings.Join(many, ",")} {
		if _, err := ParseRecipients(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseTags(t *testing.T) {
	got, err := ParseTags("prod, web,\nprod,, db")
	if err != nil || !reflect.DeepEqual(got, []string{"prod", "web", "db"}) {
		t.Fatalf("%v %v", got, err)
	}
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, "t"+strings.Repeat("x", i))
	}
	for name, in := range map[string]string{"too long": strings.Repeat("a", 65), "control": "a\x07b", "21 tags": strings.Join(many, ",")} {
		if _, err := ParseTags(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
