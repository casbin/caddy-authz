package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
)
type end struct{ }
func (e end) ServeHTTP(_ http.ResponseWriter, _ *http.Request) error {
	return nil
}

func testRequest(t *testing.T, handler Authorizer, user string, path string, method string, code int) {
	r := httptest.NewRequest(method, path, nil)
	r.SetBasicAuth(user, "123")
	w := httptest.NewRecorder()
	_ =handler.ServeHTTP(w, r,end{})

	if w.Code != code {
		t.Errorf("%s, %s, %s: %d, supposed to be %d", user, path, method, w.Code, code)
	}
}

func TestBasic(t *testing.T) {
	e, err := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	if err != nil {
		t.Errorf("can not create enforcer: %v", err)
	}

	handler := Authorizer{
		AuthConfig: struct {
			ModelPath  string
			PolicyPath string
		}{ModelPath: "authz_model.conf", PolicyPath: "authz_policy.csv"},
		Enforcer: e,
	}

	testRequest(t, handler, "alice", "/dataset1/resource1", "GET", 200)
	testRequest(t, handler, "alice", "/dataset1/resource1", "POST", 200)
	testRequest(t, handler, "alice", "/dataset1/resource2", "GET", 200)
	testRequest(t, handler, "alice", "/dataset1/resource2", "POST", 403)
}

func TestPathWildcard(t *testing.T) {
	e,err := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	if err != nil {
		t.Errorf("can not create enforcer: %v", err)
	}

	handler := Authorizer{
		AuthConfig: struct {
			ModelPath  string
			PolicyPath string
		}{ModelPath: "authz_model.conf", PolicyPath: "authz_policy.csv"},
		Enforcer: e,
	}

	testRequest(t, handler, "bob", "/dataset2/resource1", "GET", 200)
	testRequest(t, handler, "bob", "/dataset2/resource1", "POST", 200)
	testRequest(t, handler, "bob", "/dataset2/resource1", "DELETE", 200)
	testRequest(t, handler, "bob", "/dataset2/resource2", "GET", 200)
	testRequest(t, handler, "bob", "/dataset2/resource2", "POST", 403)
	testRequest(t, handler, "bob", "/dataset2/resource2", "DELETE", 403)

	testRequest(t, handler, "bob", "/dataset2/folder1/item1", "GET", 403)
	testRequest(t, handler, "bob", "/dataset2/folder1/item1", "POST", 200)
	testRequest(t, handler, "bob", "/dataset2/folder1/item1", "DELETE", 403)
	testRequest(t, handler, "bob", "/dataset2/folder1/item2", "GET", 403)
	testRequest(t, handler, "bob", "/dataset2/folder1/item2", "POST", 200)
	testRequest(t, handler, "bob", "/dataset2/folder1/item2", "DELETE", 403)
}

func TestRBAC(t *testing.T) {
	e,err := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	if err != nil {
		t.Errorf("can not create enforcer: %v", err)
	}

	handler := Authorizer{
		AuthConfig: struct {
			ModelPath  string
			PolicyPath string
		}{ModelPath: "authz_model.conf", PolicyPath: "authz_policy.csv"},
		Enforcer: e,
	}

	// cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
	testRequest(t, handler, "cathy", "/dataset1/item", "GET", 200)
	testRequest(t, handler, "cathy", "/dataset1/item", "POST", 200)
	testRequest(t, handler, "cathy", "/dataset1/item", "DELETE", 200)
	testRequest(t, handler, "cathy", "/dataset2/item", "GET", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "POST", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "DELETE", 403)

	// delete all roles on user cathy, so cathy cannot access any resources now.
	_,_ = e.DeleteRolesForUser("cathy")

	testRequest(t, handler, "cathy", "/dataset1/item", "GET", 403)
	testRequest(t, handler, "cathy", "/dataset1/item", "POST", 403)
	testRequest(t, handler, "cathy", "/dataset1/item", "DELETE", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "GET", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "POST", 403)
	testRequest(t, handler, "cathy", "/dataset2/item", "DELETE", 403)
}
