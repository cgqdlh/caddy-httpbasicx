package caddyhttpbasicx

import (
	"math/rand"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(HTTPBasicxAuth{})

	rand.Seed(time.Now().UnixNano())
}

type HTTPBasicxAuth struct {
	caddyauth.HTTPBasicAuth
	HeaderKey string `json:"header_key,omitempty"`
	logger    *zap.Logger
}

func (HTTPBasicxAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.http_basicx",
		New: func() caddy.Module { return new(HTTPBasicxAuth) },
	}
}

func (a *HTTPBasicxAuth) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger().Named("http_basicx")
	return a.HTTPBasicAuth.Provision(ctx)
}

func (a HTTPBasicxAuth) Authenticate(w http.ResponseWriter, req *http.Request) (caddyauth.User, bool, error) {
	a.logger.Debug("Request to perform basic authentication", zap.String("headerKey", a.HeaderKey))
	if a.HeaderKey == "" {
		return a.HTTPBasicAuth.Authenticate(w, req)
	}
	user, ok, err := a.HTTPBasicAuth.Authenticate(w, req)
	if err == nil && ok {
		req.Header.Set(a.HeaderKey, user.ID)
	}
	return user, ok, err
}
