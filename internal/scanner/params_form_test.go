package scanner

import "testing"

func TestParseFormFieldsPreservesValidationValues(t *testing.T) {
	fields := parseFormFields(`<form method="post">
		<input type="hidden" name="csrf" value="tok&amp;123">
		<input name="lookup" value="original">
		<textarea name="note">hello</textarea>
		<select name="tenant"><option value="a">A</option><option value="acme" selected>Acme</option></select>
		<input name="ignored" value="x" disabled>
	</form>`)
	got := map[string]string{}
	for _, f := range fields {
		got[f.name] = f.value
	}
	for name, want := range map[string]string{
		"csrf": "tok&123", "lookup": "original", "note": "hello", "tenant": "acme",
	} {
		if got[name] != want {
			t.Errorf("field %s=%q, want %q (all=%#v)", name, got[name], want, got)
		}
	}
	if _, ok := got["ignored"]; ok {
		t.Fatalf("disabled control must not be replayed: %#v", got)
	}
}
