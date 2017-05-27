Caddy-authz [![GoDoc](https://godoc.org/github.com/casbin/caddy-authz?status.svg)](https://godoc.org/github.com/casbin/caddy-authz)
======

Caddy-authz is an authorization middleware for [Caddy](https://github.com/mholt/caddy), it's based on [https://github.com/casbin/casbin](https://github.com/casbin/casbin).

## Installation

    go get github.com/casbin/caddy-authz

## Simple Example

```Go
package main

import (
	"net/http"

	"github.com/casbin/caddy-authz"
	"github.com/casbin/casbin"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func main() {
	// load the casbin model and policy from files, database is also supported.
	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")

	// define your handler, this is just an example to return HTTP 200 for any requests.
	// the access that is denied by authz will return HTTP 403 error.
	handler := authz.Authorizer{
        Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
            return http.StatusOK, nil
        }),
        Enforcer: e,
    }
}
```

## Getting Help

- [casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
