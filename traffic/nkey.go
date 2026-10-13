package traffic

import (
	"regexp"
	"strings"
)

var (
	tmplReNumeric = regexp.MustCompile(`^\d+$`)
	tmplReUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tmplReHex     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	tmplReLong    = regexp.MustCompile(`^[A-Za-z0-9_-]{24,}$`)
)

// templatePath collapses high-cardinality path segments into placeholders so the
// index/evidence are not flooded by instances: /user/123 -> /user/{id}.
//
// This is a verbatim, db-free copy of db.TemplatePath (db/nkey.go). It is
// duplicated here on purpose: the traffic subsystem must be importable by the
// sandboxed Agent binary, which may never link the Postgres `db` package. A
// ~20-line pure function is a cheap price for keeping that compile-time invariant.
// Keep the two in sync if the templating rules change.
func templatePath(path string) string {
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		switch {
		case s == "":
			continue
		case tmplReNumeric.MatchString(s):
			segs[i] = "{id}"
		case tmplReUUID.MatchString(s):
			segs[i] = "{uuid}"
		case tmplReHex.MatchString(s):
			segs[i] = "{hex}"
		case tmplReLong.MatchString(s):
			segs[i] = "{token}"
		}
	}
	return strings.Join(segs, "/")
}
