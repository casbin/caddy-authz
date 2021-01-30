package authz

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

var tester *caddytest.Tester

func testRequest(t *testing.T, user string, path string, method string, code int) {
	req, err := http.NewRequest(method, fmt.Sprintf("http://localhost:9080%s", path), nil)
	if err != nil {
		t.Fatalf("unable to create request %s", err)
	}
	req.Header.Set("Authorization", user)
	tester.AssertResponse(req, code, "")
}

func initTester(t *testing.T) {
	tester = caddytest.NewTester(t)
	tester.InitServer(` 
	{
		http_port     9080
		https_port    9443
	}
	localhost:9080 {
		route /* {
			authz "authz_model.conf" "authz_policy.csv"
			respond ""
		}
	}`, "caddyfile")
}

func TestBasic(t *testing.T) {
	initTester(t)

	testRequest(t, "alice", "/dataset1/resource1", "GET", 200)
	testRequest(t, "alice", "/dataset1/resource1", "POST", 200)
	testRequest(t, "alice", "/dataset1/resource2", "GET", 200)
	testRequest(t, "alice", "/dataset1/resource2", "POST", 403)
}

func TestPathWildcard(t *testing.T) {
	initTester(t)

	testRequest(t, "bob", "/dataset2/resource1", "GET", 200)
	testRequest(t, "bob", "/dataset2/resource1", "POST", 200)
	testRequest(t, "bob", "/dataset2/resource1", "DELETE", 200)
	testRequest(t, "bob", "/dataset2/resource2", "GET", 200)
	testRequest(t, "bob", "/dataset2/resource2", "POST", 403)
	testRequest(t, "bob", "/dataset2/resource2", "DELETE", 403)

	testRequest(t, "bob", "/dataset2/folder1/item1", "GET", 403)
	testRequest(t, "bob", "/dataset2/folder1/item1", "POST", 200)
	testRequest(t, "bob", "/dataset2/folder1/item1", "DELETE", 403)
	testRequest(t, "bob", "/dataset2/folder1/item2", "GET", 403)
	testRequest(t, "bob", "/dataset2/folder1/item2", "POST", 200)
	testRequest(t, "bob", "/dataset2/folder1/item2", "DELETE", 403)
}

func TestRBAC(t *testing.T) {
	initTester(t)

	// cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
	testRequest(t, "cathy", "/dataset1/item", "GET", 200)
	testRequest(t, "cathy", "/dataset1/item", "POST", 200)
	testRequest(t, "cathy", "/dataset1/item", "DELETE", 200)
	testRequest(t, "cathy", "/dataset2/item", "GET", 403)
	testRequest(t, "cathy", "/dataset2/item", "POST", 403)
	testRequest(t, "cathy", "/dataset2/item", "DELETE", 403)
}
