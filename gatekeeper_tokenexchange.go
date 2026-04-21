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
	Grant            string
	Header           string
	Prefix           string
	Format           string
}

func newTokenExchangeResolver(cfg tokenExchangeResolverConfig) proxy.CredentialResolver {
	src := credentialsource.NewTokenExchangeSource(credentialsource.TokenExchangeConfig{
		Endpoint:         cfg.Endpoint,
		ClientID:         cfg.ClientID,
		ClientSecret:     cfg.ClientSecret,
		Resource:         cfg.Resource,
		SubjectTokenType: cfg.SubjectTokenType,
		ActorTokenType:   cfg.ActorTokenType,
	})

	header := cfg.Header
	if header == "" {
		header = "Authorization"
	}

	return func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]proxy.CredentialHeader, error) {
		var subject, actorToken string
		switch cfg.SubjectFrom {
		case "proxy-auth":
			var password string
			subject, password = extractProxyAuthCredentials(proxyReq)
			if cfg.ActorTokenFrom == "proxy-auth-password" {
				if password == "" {
					return nil, fmt.Errorf("actor_token_from %q requires a proxy auth password", cfg.ActorTokenFrom)
				}
				actorToken = password
			}
		default:
			subject = innerReq.Header.Get(cfg.SubjectHeader)
			if subject != "" {
				innerReq.Header.Del(cfg.SubjectHeader)
			}
		}

		if subject == "" {
			return nil, nil
		}

		token, err := src.Resolve(ctx, subject, actorToken)
		if err != nil {
			return nil, err
		}

		value := ensureAuthScheme(token, cfg.Prefix, cfg.Format)

		return []proxy.CredentialHeader{{
			Name:  header,
			Value: value,
			Grant: cfg.Grant,
		}}, nil
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
	if cfg.ClientSecret == "" && cfg.ClientSecretEnv == "" {
		return nil, fmt.Errorf("token-exchange source requires 'client_secret' or 'client_secret_env' field")
	}
	if cfg.ClientSecret != "" && cfg.ClientSecretEnv != "" {
		return nil, fmt.Errorf("token-exchange source: set 'client_secret' or 'client_secret_env', not both")
	}
	// Reject extraneous fields from other source types
	if cfg.Var != "" || cfg.Value != "" || cfg.Secret != "" || cfg.Region != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" {
		return nil, fmt.Errorf("token-exchange source only uses 'endpoint', 'client_id', 'client_secret'/'client_secret_env', 'subject_header'/'subject_from', 'actor_token_from', 'actor_token_type', 'subject_token_type', and 'resource'; found extraneous fields")
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
		Grant:            cred.Grant,
		Header:           header,
		Prefix:           cred.Prefix,
		Format:           cred.Format,
	}), nil
}
