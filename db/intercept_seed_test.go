package db

import (
	"regexp"
	"testing"
)

// The built-in "delete-type endpoint path" rule matches against the entire tool_input JSON string, so the
// cases are given directly in JSON form, consistent with the subject the Interceptor actually receives.
func TestDeleteEndpointPathPattern(t *testing.T) {
	re := regexp.MustCompile(deleteEndpointPathPattern)

	hit := []string{
		`{"command":"curl -s 'http://t.com/api/user/delete?id=1'"}`,    // GET hitting a delete endpoint
		`{"command":"curl -X POST http://t.com/admin/delete -d id=1"}`, // POST hitting a delete endpoint
		`{"command":"curl 'http://t.com/api/deleteAll'"}`,
		`{"command":"curl 'http://t.com/api/delete_user?id=1'"}`,
		`{"command":"curl 'http://t.com/api/delete-user?id=1'"}`,
		`{"url":"http://t.com/api/remove?id=1"}`,
		`{"command":"curl http://t.com/files/unlink/3"}`,
		`{"command":"curl http://t.com/api/del?id=2"}`,
		`{"command":"curl -X POST http://t/v1/erase"}`,
		`{"command":"curl http://t/admin/destroyAll"}`, // v1's path rule did not allow a suffix; added here
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("should have matched but was allowed: %s", s)
		}
	}

	// A separator must follow the verb, to avoid mis-intercepting read-only paths like /delivery or /details.
	miss := []string{
		`{"command":"curl 'http://t.com/api/delivery?id=1'"}`,
		`{"command":"curl 'http://t.com/order/details'"}`,
		`{"command":"curl 'http://t.com/api/delta/sync'"}`,
		`{"command":"curl 'http://t.com/user/delegate'"}`,
		`{"command":"curl 'http://delete.example.com/'"}`, // the delete verb appears in the domain, not the path
		`{"command":"curl 'http://t.com/remote/status'"}`,
		`{"command":"nmap -p80 10.0.0.1"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("falsely intercepted: %s", s)
		}
	}
}
