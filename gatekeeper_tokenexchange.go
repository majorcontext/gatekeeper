package gatekeeper

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/majorcontext/gatekeeper/credentialsource"
	"github.com/majorcontext/gatekeeper/proxy"
)

type tokenExchangeResolverConfig struct {
	Endpoint         string
	ClientID         string
	ClientSecret     string
	Resource         string
	SubjectTokenType string
	ActorTokenType   string
	SubjectHeader    string
	SubjectFrom      string
	ActorTokenFrom   string
	BotSubject       string
	Grant            string
	Header           string
	Prefix           string
	Format           string
}

func newTokenExchangeResolver(cfg tokenExchangeResolverConfig) proxy.CredentialResolver {
	resolve := credentialsource.TokenExchangeResolver(credentialsource.TokenExchangeResolverConfig{
		TokenExchangeConfig: credentialsource.TokenExchangeConfig{
			Endpoint:         cfg.Endpoint,
			ClientID:         cfg.ClientID,
			ClientSecret:     cfg.ClientSecret,
			Resource:         cfg.Resource,
			SubjectTokenType: cfg.SubjectTokenType,
			ActorTokenType:   cfg.ActorTokenType,
		},
		SubjectHeader:  cfg.SubjectHeader,
		SubjectFrom:    cfg.SubjectFrom,
		ActorTokenFrom: cfg.ActorTokenFrom,
		BotSubject:     cfg.BotSubject,
		Grant:          cfg.Grant,
		Header:         cfg.Header,
		Prefix:         cfg.Prefix,
		Format:         cfg.Format,
		ProxyAuth:      extractProxyAuthCredentials,
		RequestID:      proxy.RequestIDFromContext,
		AuthValue:      ensureAuthScheme,
	})
	return func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]proxy.CredentialHeader, error) {
		headers, err := resolve(ctx, proxyReq, innerReq, host)
		if err != nil {
			return nil, err
		}
		if headers == nil {
			return nil, nil
		}
		out := make([]proxy.CredentialHeader, len(headers))
		for i, h := range headers {
			out[i] = proxy.CredentialHeader{Name: h.Name, Value: h.Value, Grant: h.Grant, Invalidate: h.Invalidate}
		}
		return out, nil
	}
}

func extractProxyAuthCredentials(r *http.Request) (username, password string) {
	if r == nil {
		return "", ""
	}
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", ""
	}
	if !strings.HasPrefix(auth, "Basic ") {
		return "", ""
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", ""
	}
	u, p, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", ""
	}
	return u, p
}

func resolveTokenExchange(cred CredentialConfig) (proxy.CredentialResolver, error) {
	cfg := cred.Source
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("token-exchange source requires 'endpoint' field")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("token-exchange source requires 'client_id' field")
	}
	if cfg.SubjectHeader != "" && cfg.SubjectFrom != "" {
		return nil, fmt.Errorf("token-exchange source: set 'subject_header' or 'subject_from', not both")
	}
	if cfg.SubjectHeader == "" && cfg.SubjectFrom == "" {
		return nil, fmt.Errorf("token-exchange source requires 'subject_header' or 'subject_from' field")
	}
	if cfg.SubjectFrom != "" && cfg.SubjectFrom != "proxy-auth" {
		return nil, fmt.Errorf("token-exchange source: unsupported subject_from value %q (supported: proxy-auth)", cfg.SubjectFrom)
	}
	if cfg.ActorTokenFrom != "" && cfg.ActorTokenFrom != "proxy-auth-password" {
		return nil, fmt.Errorf("token-exchange source: unsupported actor_token_from value %q (supported: proxy-auth-password)", cfg.ActorTokenFrom)
	}
	if cfg.ActorTokenFrom == "proxy-auth-password" && cfg.SubjectFrom != "proxy-auth" {
		return nil, fmt.Errorf("token-exchange source: actor_token_from 'proxy-auth-password' requires subject_from 'proxy-auth'")
	}
	if cfg.BotSubject != "" && cfg.SubjectFrom != "proxy-auth" {
		// subject_header mode reads a caller-controlled, self-asserted
		// header -- unlike subject_from: proxy-auth, nothing authenticates
		// it. Allowing bot_subject there would let any caller send the
		// configured sentinel value in that header to skip the STS and
		// fall through to the credential below (typically broader, e.g. a
		// github-app bot rule), bypassing per-subject authentication for
		// the host entirely. Config-time rejection here is the first of
		// two layers; credentialsource.TokenExchangeResolver's own runtime check on
		// cfg.SubjectFrom == "proxy-auth" is the second, so the property
		// holds even for a resolver built some other way than through this
		// function.
		return nil, fmt.Errorf("token-exchange source: bot_subject requires subject_from 'proxy-auth'")
	}
	if cfg.ClientSecret == "" && cfg.ClientSecretEnv == "" {
		return nil, fmt.Errorf("token-exchange source requires 'client_secret' or 'client_secret_env' field")
	}
	if cfg.ClientSecret != "" && cfg.ClientSecretEnv != "" {
		return nil, fmt.Errorf("token-exchange source: set 'client_secret' or 'client_secret_env', not both")
	}
	// Reject extraneous fields from other source types
	if cfg.Var != "" || cfg.Value != "" || cfg.Command != "" || cfg.TTL != "" || cfg.Secret != "" || cfg.Region != "" || cfg.Project != "" || cfg.Version != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" || cfg.Scopes != "" {
		return nil, fmt.Errorf("token-exchange source only uses 'endpoint', 'client_id', 'client_secret'/'client_secret_env', 'subject_header'/'subject_from', 'bot_subject', 'actor_token_from', 'actor_token_type', 'subject_token_type', and 'resource'; found extraneous fields")
	}

	clientSecret := cfg.ClientSecret
	if cfg.ClientSecretEnv != "" {
		clientSecret = os.Getenv(cfg.ClientSecretEnv)
		if clientSecret == "" {
			return nil, fmt.Errorf("environment variable %s is not set", cfg.ClientSecretEnv)
		}
	}

	header := cred.Header
	if header == "" {
		header = "Authorization"
	}

	return newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:         cfg.Endpoint,
		ClientID:         cfg.ClientID,
		ClientSecret:     clientSecret,
		Resource:         cfg.Resource,
		SubjectTokenType: cfg.SubjectTokenType,
		ActorTokenType:   cfg.ActorTokenType,
		SubjectHeader:    cfg.SubjectHeader,
		SubjectFrom:      cfg.SubjectFrom,
		ActorTokenFrom:   cfg.ActorTokenFrom,
		BotSubject:       cfg.BotSubject,
		Grant:            cred.Grant,
		Header:           header,
		Prefix:           cred.Prefix,
		Format:           cred.Format,
	}), nil
}

func tokenExchangeStripHeaders(cred CredentialConfig) []string {
	if cred.Source.Type != "token-exchange" {
		return nil
	}
	return credentialsource.TokenExchangeStripHeaders(cred.Source.SubjectHeader)
}
