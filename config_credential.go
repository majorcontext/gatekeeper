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
		if cfg.Value != "" || cfg.Secret != "" || cfg.Region != "" || cfg.Project != "" || cfg.Version != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" || cfg.Scopes != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectFrom != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" || cfg.ActorTokenFrom != "" || cfg.ActorTokenType != "" {
			return nil, fmt.Errorf("env source only uses 'var'; found extraneous fields")
		}
		return credentialsource.NewEnvSource(cfg.Var), nil
	case "static":
		if cfg.Value == "" {
			return nil, fmt.Errorf("static source requires 'value' field")
		}
		if cfg.Var != "" || cfg.Secret != "" || cfg.Region != "" || cfg.Project != "" || cfg.Version != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" || cfg.Scopes != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectFrom != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" || cfg.ActorTokenFrom != "" || cfg.ActorTokenType != "" {
			return nil, fmt.Errorf("static source only uses 'value'; found extraneous fields")
		}
		return credentialsource.NewStaticSource(cfg.Value), nil
	case "aws-secretsmanager":
		if cfg.Secret == "" {
			return nil, fmt.Errorf("aws-secretsmanager source requires 'secret' field")
		}
		if cfg.Var != "" || cfg.Value != "" || cfg.Project != "" || cfg.Version != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" || cfg.Scopes != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectFrom != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" || cfg.ActorTokenFrom != "" || cfg.ActorTokenType != "" {
			return nil, fmt.Errorf("aws-secretsmanager source only uses 'secret' and 'region'; found extraneous fields")
		}
		return credentialsource.NewAWSSecretsManagerSource(cfg.Secret, cfg.Region)
	case "gcp-secretmanager":
		if cfg.Secret == "" {
			return nil, fmt.Errorf("gcp-secretmanager source requires 'secret' field")
		}
		if cfg.Project == "" {
			return nil, fmt.Errorf("gcp-secretmanager source requires 'project' field")
		}
		if cfg.Var != "" || cfg.Value != "" || cfg.Region != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != "" || cfg.Scopes != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectFrom != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" || cfg.ActorTokenFrom != "" || cfg.ActorTokenType != "" {
			return nil, fmt.Errorf("gcp-secretmanager source only uses 'secret', 'project', and 'version'; found extraneous fields")
		}
		return credentialsource.NewGCPSecretManagerSource(cfg.Project, cfg.Secret, cfg.Version)
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
		if cfg.Var != "" || cfg.Value != "" || cfg.Secret != "" || cfg.Region != "" || cfg.Project != "" || cfg.Version != "" || cfg.Scopes != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectFrom != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" || cfg.ActorTokenFrom != "" || cfg.ActorTokenType != "" {
			return nil, fmt.Errorf("github-app source only uses 'app_id', 'installation_id', and one of 'private_key_path'/'private_key_env'; found extraneous fields")
		}
		keyPEM, err := readKeyMaterial(cfg.PrivateKeyPath, cfg.PrivateKeyEnv)
		if err != nil {
			return nil, err
		}
		return credentialsource.NewGitHubAppSource(cfg.AppID, cfg.InstallationID, keyPEM)
	case "gcp-service-account":
		keyLocations := 0
		for _, set := range []bool{cfg.PrivateKeyPath != "", cfg.PrivateKeyEnv != "", cfg.Secret != ""} {
			if set {
				keyLocations++
			}
		}
		if keyLocations == 0 {
			return nil, fmt.Errorf("gcp-service-account source requires a key location: 'private_key_path', 'private_key_env', or 'secret' (with 'project')")
		}
		if keyLocations > 1 {
			return nil, fmt.Errorf("gcp-service-account source: set only one of 'private_key_path', 'private_key_env', or 'secret'")
		}
		if cfg.Secret != "" && cfg.Project == "" {
			return nil, fmt.Errorf("gcp-service-account source requires 'project' when reading the key from Secret Manager via 'secret'")
		}
		if cfg.Secret == "" && (cfg.Project != "" || cfg.Version != "") {
			return nil, fmt.Errorf("gcp-service-account source only uses 'project' and 'version' with 'secret'")
		}
		if cfg.Var != "" || cfg.Value != "" || cfg.Region != "" || cfg.AppID != "" || cfg.InstallationID != "" || cfg.Endpoint != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.ClientSecretEnv != "" || cfg.SubjectHeader != "" || cfg.SubjectFrom != "" || cfg.SubjectTokenType != "" || cfg.Resource != "" || cfg.ActorTokenFrom != "" || cfg.ActorTokenType != "" {
			return nil, fmt.Errorf("gcp-service-account source only uses a key location ('private_key_path', 'private_key_env', or 'secret'/'project'/'version') and 'scopes'; found extraneous fields")
		}
		if cfg.Secret != "" {
			keySource, err := credentialsource.NewGCPSecretManagerSource(cfg.Project, cfg.Secret, cfg.Version)
			if err != nil {
				return nil, err
			}
			return credentialsource.NewGCPServiceAccountSourceFromKeySource(keySource, cfg.Scopes), nil
		}
		keyJSON, err := readKeyMaterial(cfg.PrivateKeyPath, cfg.PrivateKeyEnv)
		if err != nil {
			return nil, err
		}
		return credentialsource.NewGCPServiceAccountSource(keyJSON, cfg.Scopes)
	default:
		return nil, fmt.Errorf("unknown credential source type: %q", cfg.Type)
	}
}

// readKeyMaterial loads key material from a file path or an environment
// variable, exactly one of which must be set (validated by the caller).
func readKeyMaterial(path, env string) ([]byte, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}
		return data, nil
	}
	val := os.Getenv(env)
	if val == "" {
		return nil, fmt.Errorf("environment variable %s is not set", env)
	}
	return []byte(val), nil
}

// ResolveCredentialSource creates either a static CredentialSource or a dynamic
// CredentialResolver from a credential config. For static sources (env, static,
// aws-secretsmanager, gcp-secretmanager, gcp-service-account, github-app), the
// first return is non-nil. For dynamic sources (token-exchange), the second
// return is non-nil.
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
