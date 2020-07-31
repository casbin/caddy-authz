package authz

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/casbin/casbin/v2"
)

func init() {
	caddy.RegisterModule(Authorizer{})
	httpcaddyfile.RegisterHandlerDirective("authz", parseCaddyfile)
}

type Authorizer struct {
	AuthConfig struct {
		ModelPath  string
		PolicyPath string
	}
	Enforcer *casbin.Enforcer
}

// CaddyModule returns the Caddy module information.
func (Authorizer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.authz",
		New: func() caddy.Module { return new(Authorizer) },
	}
}

// Provision implements caddy.Provisioner.
func (a *Authorizer) Provision(ctx caddy.Context) error {
	e, err := casbin.NewEnforcer(a.AuthConfig.ModelPath, a.AuthConfig.PolicyPath)
	if err != nil {
		return err
	}
	a.Enforcer = e
	return nil
}

// Validate implements caddy.Validator.
func (a *Authorizer) Validate() error {
	if a.Enforcer == nil {
		return fmt.Errorf("no Enforcer")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (a Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	allowed, err := a.CheckPermission(r)
	if err != nil {
		return err
	}

	if !allowed {
		w.WriteHeader(403)
		return nil
	}

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (a *Authorizer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		a.AuthConfig.ModelPath = d.Val()
		if !d.NextArg() {
			return d.ArgErr()
		}
		a.AuthConfig.PolicyPath = d.Val()
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Authorizer.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	fmt.Println("parse")
	var m Authorizer
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *Authorizer) GetUserName(r *http.Request) string {
	username, _, _ := r.BasicAuth()
	return username
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *Authorizer) CheckPermission(r *http.Request) (bool, error) {
	user := a.GetUserName(r)
	method := r.Method
	path := r.URL.Path
	return a.Enforcer.Enforce(user, path, method)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Authorizer)(nil)
	_ caddy.Validator             = (*Authorizer)(nil)
	_ caddyhttp.MiddlewareHandler = (*Authorizer)(nil)
	_ caddyfile.Unmarshaler       = (*Authorizer)(nil)
)
