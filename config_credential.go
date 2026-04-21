package gatekeeper

import (
	"fmt"
	"os"

	"github.com/majorcontext/gatekeeper/credentialsource"
	"github.com/majorcontext/gatekeeper/proxy"
)

// ResolveSource creates a CredentialSource from a SourceConfig.
// Returns an error if the config contains fields not relevant to the selected type.
func ResolveSource(cfg SourceConfig) (credentialsource.CredentialSource, error) {
	switch cfg.Type {
	case "env":
		if cfg.Var == "" {
			return nil, fmt.Errorf("env source requires 'var' field")
		}
		if cfg.Value != "" || cfg.Secret != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" {
			return nil, fmt.Errorf("env source only uses 'var'; found extraneous fields")
		}
		return credentialsource.NewEnvSource(cfg.Var), nil
	case "static":
		if cfg.Value == "" {
			return nil, fmt.Errorf("static source requires 'value' field")
		}
		if cfg.Var != "" || cfg.Secret != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" {
			return nil, fmt.Errorf("static source only uses 'value'; found extraneous fields")
		}
		return credentialsource.NewStaticSource(cfg.Value), nil
	case "aws-secretsmanager":
		if cfg.Secret == "" {
			return nil, fmt.Errorf("aws-secretsmanager source requires 'secret' field")
		}
		if cfg.Var != "" || cfg.Value != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" {
			return nil, fmt.Errorf("aws-secretsmanager source only uses 'secret' and 'region'; found extraneous fields")
		}
		return credentialsource.NewAWSSecretsManagerSource(cfg.Secret, cfg.Region)
	case "github-app":
		if cfg.AppID == "" {
			return nil, fmt.Errorf("github-app source requires 'app_id' field")
		}
		if cfg.InstallationID == "" {
			return nil, fmt.Errorf("github-app source requires 'installation_id' field")
		}
		if cfg.PrivateKeyPath == "" && cfg.PrivateKeyEnv == "" {
			return nil, fmt.Errorf("github-app source requires 'private_key_path' or 'private_key_env' field")
		}
		if cfg.PrivateKeyPath != "" && cfg.PrivateKeyEnv != "" {
			return nil, fmt.Errorf("github-app source: set 'private_key_path' or 'private_key_env', not both")
		}
		if cfg.Var != "" || cfg.Value != "" || cfg.Secret != "" || cfg.Region != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" {
			return nil, fmt.Errorf("github-app source only uses 'app_id', 'installation_id', and one of 'private_key_path'/'private_key_env'; found extraneous fields")
		}
		var keyPEM []byte
		if cfg.PrivateKeyPath != "" {
			var err error
			keyPEM, err = os.ReadFile(cfg.PrivateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("reading private key file: %w", err)
			}
		} else {
			val := os.Getenv(cfg.PrivateKeyEnv)
			if val == "" {
				return nil, fmt.Errorf("environment variable %s is not set", cfg.PrivateKeyEnv)
			}
			keyPEM = []byte(val)
		}
		return credentialsource.NewGitHubAppSource(cfg.AppID, cfg.InstallationID, keyPEM)
	default:
		return nil, fmt.Errorf("unknown credential source type: %q", cfg.Type)
	}
}

// ResolveCredentialSource creates either a static CredentialSource or a dynamic
// CredentialResolver from a credential config. For static sources (env, static,
// aws-secretsmanager, github-app), the first return is non-nil. For dynamic
// sources (token-exchange), the second return is non-nil.
func ResolveCredentialSource(cred CredentialConfig) (credentialsource.CredentialSource, proxy.CredentialResolver, error) {
	switch cred.Source.Type {
	case "token-exchange":
		resolver, err := resolveTokenExchange(cred)
		return nil, resolver, err
	default:
		src, err := ResolveSource(cred.Source)
		return src, nil, err
	}
}
