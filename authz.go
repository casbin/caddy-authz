package authz

import (
	"github.com/casbin/casbin"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"net/http"
)

// Authorizer is a middleware for filtering clients based on their ip or country's ISO code.
type Authorizer struct {
	Next     httpserver.Handler
	Enforcer *casbin.Enforcer
}

// Init initializes the plugin
func init() {
	caddy.RegisterPlugin("authz", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

// GetConfig gets the config path that corresponds to c.
func GetConfig(c *caddy.Controller) string {
	for c.Next() {              // skip the directive name
		if !c.NextArg() {       // expect at least one value
			return c.ArgErr().Error()   // otherwise it's an error
		}
		return c.Val()        // use the value
	}
	return "No Casbin config path found."
}

// Setup parses the Casbin configuration and returns the middleware handler.
func Setup(c *caddy.Controller) error {
	conf := GetConfig(c)
	e := casbin.NewEnforcer(conf)

	// Create new middleware
	newMiddleWare := func(next httpserver.Handler) httpserver.Handler {
		return &Authorizer{
			Next:     next,
			Enforcer: e,
		}
	}
	// Add middleware
	cfg := httpserver.GetConfig(c)
	cfg.AddMiddleware(newMiddleWare)

	return nil
}

// ServeHTTP serves the request.
func (a Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !a.CheckPermission(r) {
		w.WriteHeader(403)
		return http.StatusForbidden, nil
	} else {
		return a.Next.ServeHTTP(w, r)
	}
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *Authorizer) GetUserName(r *http.Request) string {
	username, _, _ := r.BasicAuth()
	return username
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *Authorizer) CheckPermission(r *http.Request) bool {
	user := a.GetUserName(r)
	method := r.Method
	path := r.URL.Path
	return a.Enforcer.Enforce(user, path, method)
}
