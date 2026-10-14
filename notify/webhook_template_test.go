package notify

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// This file pins the **capability boundary** of the generic Webhook template.
//
// This is the only place in the whole package where "a user-provided string is evaluated as code", so it must be clear what it can
// and cannot do, with tests nailing these properties down — otherwise someone later casually adds a
// method to the template context, or a readFile in the FuncMap, and the capability surface silently expands while the diff looks like
// just a harmless little function.

// TestTemplateContextHasNoMethods is the most important one.
//
// text/template calls exported methods ({{.Foo}} can fetch a field or call a method). So if the template context
// can reach **any** type with exported methods, it exposes those methods to the template author.
// This feature's context is deliberately all pure data (only exported fields, zero methods).
//
// If this fails: someone added a method to webhookTemplateData / webhookItem.
// Before deciding to allow it, think through whether that method could be used by a template to read something that should not be exposed.
func TestTemplateContextHasNoMethods(t *testing.T) {
	for _, v := range []any{webhookTemplateData{}, webhookItem{}} {
		typ := reflect.TypeOf(v)
		if n := typ.NumMethod(); n != 0 {
			var names []string
			for i := 0; i < n; i++ {
				names = append(names, typ.Method(i).Name)
			}
			t.Fatalf("%s exposes %d methods (%s): text/template can call them, "+
				"which opens those methods' capabilities to the template author", typ.Name(), n, strings.Join(names, ", "))
		}
	}
}

// TestTemplateFuncsAreMinimal pins the set of functions exposed to the template.
//
// Every extra function in the FuncMap is one more capability. Currently only json / jsons, whose job is to serialize values
// into JSON fragments — they cannot read files, make requests, or execute commands.
func TestTemplateFuncsAreMinimal(t *testing.T) {
	var got []string
	for name := range webhookTemplateFuncs {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"json", "jsons"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the template function set changed: got %v, expected %v. Before adding a function, confirm it does not expand the capability surface "+
			"(no file read/write, no network requests, no command execution)", got, want)
	}
}

// TestTemplateCannotReachUnknownData covers out-of-bounds access in the template:
// accessing something that does not exist must fail rather than echo something, and the failure message must not carry out internal data.
func TestTemplateCannotReachUnknownData(t *testing.T) {
	_, err := renderWebhookBody(`{"x": {{.Environment}}, "y": {{.Env}}}`, singleMsg())
	if err == nil {
		t.Fatal("accessing a non-existent field should error")
	}
	// The error must not contain real content from the template context (finding title/summary).
	for _, leak := range []string{"SQL injection", "parameter id"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the template error leaked message content %q: %v", leak, err)
		}
	}
}

// TestTemplateRenderFailsPermanently: a wrong template is a config error that retrying will not heal.
// If judged retryable, one bad template would make every delivery waste three backoff rounds.
func TestTemplateRenderFailsPermanently(t *testing.T) {
	cfg := map[string]any{
		"url":           "https://example.com/hook",
		"body_template": `{{.Items.`,
	}
	if err := (webhookChannel{}).Validate(cfg); err == nil {
		t.Fatal("a template syntax error should be caught at save time")
	}
	// Even bypassing validation and delivering directly, it must be judged a permanent failure rather than retried repeatedly.
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a bad template should be judged a permanent failure, got %v", err)
	}
}

// TestTemplateCanOnlyProduceJSON covers the constraint that "the template render result must be valid JSON".
// It also incidentally blocks uses like "generate plain text with the template to trigger another protocol".
func TestTemplateCanOnlyProduceJSON(t *testing.T) {
	// A valid template passes.
	ok := map[string]any{"url": "https://example.com/hook", "body_template": `{"t":{{json .Title}}}`}
	if err := (webhookChannel{}).Validate(ok); err != nil {
		t.Fatalf("a valid template should pass validation: %v", err)
	}
	// When it renders non-JSON it must be rejected (not sent as-is).
	bad := map[string]any{"url": "http://127.0.0.1:1/hook", "body_template": `not json {{.Count}}`}
	_, err := (webhookChannel{}).Send(context.Background(), bad, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("rendering non-JSON should be judged a permanent failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "올바른 JSON") {
		t.Errorf("the error message should indicate it is a JSON problem, got %v", err)
	}
}
