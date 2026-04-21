package gatekeeper

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/majorcontext/gatekeeper/credentialsource"
	"github.com/majorcontext/gatekeeper/proxy"
)

type tokenExchangeResolverConfig struct {
	Endpoint         string
	ClientID         string
	ClientSecret     string
	Resource         string
	SubjectTokenType string
	SubjectHeader    string
	Grant            string
	Header           string
	Prefix           string
}

func newTokenExchangeResolver(cfg tokenExchangeResolverConfig) proxy.CredentialResolver {
	src := credentialsource.NewTokenExchangeSource(credentialsource.TokenExchangeConfig{
		Endpoint:         cfg.Endpoint,
		ClientID:         cfg.ClientID,
		ClientSecret:     cfg.ClientSecret,
		Resource:         cfg.Resource,
		SubjectTokenType: cfg.SubjectTokenType,
	})

	header := cfg.Header
	if header == "" {
		header = "Authorization"
	}

	return func(ctx context.Context, req *http.Request, host string) ([]proxy.CredentialHeader, error) {
		subject := req.Header.Get(cfg.SubjectHeader)
		if subject == "" {
			return nil, nil
		}
		req.Header.Del(cfg.SubjectHeader)

		token, err := src.Resolve(ctx, subject)
		if err != nil {
			return nil, err
		}

		value := token
		if cfg.Prefix != "" {
			value = cfg.Prefix + " " + token
		}

		return []proxy.CredentialHeader{{
			Name:  header,
			Value: value,
			Grant: cfg.Grant,
		}}, nil
	}
}

func resolveTokenExchange(cred CredentialConfig) (proxy.CredentialResolver, error) {
	cfg := cred.Source
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("token-exchange source requires 'endpoint' field")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("token-exchange source requires 'client_id' field")
	}
	if cfg.SubjectHeader == "" {
		return nil, fmt.Errorf("token-exchange source requires 'subject_header' field")
	}
	if cfg.ClientSecret == "" && cfg.ClientSecretEnv == "" {
		return nil, fmt.Errorf("token-exchange source requires 'client_secret' or 'client_secret_env' field")
	}
	if cfg.ClientSecret != "" && cfg.ClientSecretEnv != "" {
		return nil, fmt.Errorf("token-exchange source: set 'client_secret' or 'client_secret_env', not both")
	}
	// Reject extraneous fields from other source types
	if cfg.Var != "" || cfg.Value != "" || cfg.Secret != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" {
		return nil, fmt.Errorf("token-exchange source only uses 'endpoint', 'client_id', 'client_secret'/'client_secret_env', 'subject_header', 'subject_token_type', and 'resource'; found extraneous fields")
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
		SubjectHeader:    cfg.SubjectHeader,
		Grant:            cred.Grant,
		Header:           header,
		Prefix:           cred.Prefix,
	}), nil
}
