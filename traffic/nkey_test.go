package traffic

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// templatePath is a db-free copy of db.TemplatePath so the traffic subsystem can
// be hosted by the Agent binary (which must never link the Postgres `db`
// package). This guards the two against drift. The test lives in Management's
// build context, so importing `db` here is fine; the Agent binary never does.
func TestTemplatePathParity(t *testing.T) {
	cases := []string{
		"",
		"/",
		"/user/123",
		"/user/123/posts/456",
		"/orders/550e8400-e29b-41d4-a716-446655440000",
		"/blob/deadbeefdeadbeefdeadbeef",
		"/t/AbCdEfGhIjKlMnOpQrStUvWx",
		"/a/b/c",
		"/static/app.js",
		"/mixed/42/uuid/550e8400-e29b-41d4-a716-446655440000/x",
	}
	for _, p := range cases {
		if got, want := templatePath(p), db.TemplatePath(p); got != want {
			t.Errorf("templatePath(%q)=%q, db.TemplatePath=%q (drift)", p, got, want)
		}
	}
}
