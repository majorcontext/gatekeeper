package credentialsource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// ResolvedHeader is one header produced by a TokenExchangeResolver. It carries
// the subset of the proxy package's credential header that a resolver sets.
type ResolvedHeader struct {
	Name       string
	Value      string
	Grant      string
	Invalidate func()
	Upgrade    UpgradeHint
}

// HeaderResolver resolves headers for one request. Its signature matches
// proxy.CredentialResolver apart from the result element type.
type HeaderResolver func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]ResolvedHeader, error)

// TokenExchangeResolverConfig configures TokenExchangeResolver.
type TokenExchangeResolverConfig struct {
	TokenExchangeConfig
	// Source, when set, serves the exchanges so several resolvers share one
	// cache. Nil builds a source from TokenExchangeConfig.
	Source *TokenExchangeSource

	SubjectHeader  string
	SubjectFrom    string
	ActorTokenFrom string
	BotSubject     string
	Grant          string
	Header         string
	Prefix         string
	Format         string

	// ProxyAuth returns the user and password of the request's proxy
	// authentication, or empty strings when it has none. Nil means no
	// request has proxy authentication.
	ProxyAuth func(*http.Request) (user, password string)
	// RequestID returns the request ID carried by ctx. Nil means no ID.
	RequestID func(context.Context) string
	// AuthValue turns an exchanged token into the header value. Nil uses
	// the token as is.
	AuthValue func(token, prefix, format string) string
}

// TokenExchangeResolver returns a per-request resolver that exchanges the
// caller's subject for an access token through one shared TokenExchangeSource.
// When the STS declines, the resolver returns *TokenExchangeDeclined with
// Invalidate set.
func TokenExchangeResolver(cfg TokenExchangeResolverConfig) HeaderResolver {
	src := cfg.Source
	if src == nil {
		src = NewTokenExchangeSource(cfg.TokenExchangeConfig)
	}

	if cfg.ProxyAuth == nil {
		cfg.ProxyAuth = func(*http.Request) (string, string) { return "", "" }
	}
	if cfg.RequestID == nil {
		cfg.RequestID = func(context.Context) string { return "" }
	}
	if cfg.AuthValue == nil {
		cfg.AuthValue = func(token, _, _ string) string { return token }
	}

	header := cfg.Header
	if header == "" {
		header = "Authorization"
	}

	return func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]ResolvedHeader, error) {
		var subject, actorToken string
		switch cfg.SubjectFrom {
		case "proxy-auth":
			var password string
			subject, password = cfg.ProxyAuth(proxyReq)
			if cfg.ActorTokenFrom == "proxy-auth-password" {
				if password == "" {
					return nil, fmt.Errorf("actor_token_from %q requires a proxy auth password", cfg.ActorTokenFrom)
				}
				actorToken = password
			}
		default:
			// TokenExchangeStripHeaders declares this deletion to the proxy.
			subject = innerReq.Header.Get(cfg.SubjectHeader)
			if subject != "" {
				innerReq.Header.Del(cfg.SubjectHeader)
			}
		}

		// The SubjectFrom check keeps a self-asserted subject_header value
		// from matching the sentinel and skipping the exchange.
		if subject == "" || (cfg.SubjectFrom == "proxy-auth" && cfg.BotSubject != "" && subject == cfg.BotSubject) {
			return nil, nil
		}

		token, err := src.ResolveToken(ctx, subject, actorToken, cfg.RequestID(ctx))
		// Destination rejection means the credential behind the exchange
		// rotated, or a grant changed since a decline; the source rate-limits
		// eviction.
		invalidate := func() { src.Invalidate(subject, actorToken) }
		var declined *TokenExchangeDeclined
		if errors.As(err, &declined) {
			return nil, &TokenExchangeDeclined{Upgrade: declined.Upgrade, Invalidate: invalidate}
		}
		if err != nil {
			return nil, err
		}

		return []ResolvedHeader{{
			Name:       header,
			Value:      cfg.AuthValue(token.AccessToken, cfg.Prefix, cfg.Format),
			Grant:      cfg.Grant,
			Invalidate: invalidate,
			Upgrade:    token.Upgrade,
		}}, nil
	}
}

// TokenExchangeStripHeaders returns the request headers that a
// TokenExchangeResolver with the given subject header deletes from the
// request. The proxy sanitizes them even when a static credential outranks
// the resolver.
func TokenExchangeStripHeaders(subjectHeader string) []string {
	if subjectHeader == "" {
		return nil
	}
	return []string{subjectHeader}
}
