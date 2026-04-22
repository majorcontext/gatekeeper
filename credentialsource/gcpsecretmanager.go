package credentialsource

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// GCPSecretManagerClient abstracts the GCP Secret Manager API for testing.
type GCPSecretManagerClient interface {
	AccessSecretVersion(ctx context.Context, resourceName string) (string, error)
}

type gcpSMSource struct {
	resourceName string
	client       GCPSecretManagerClient
}

// NewGCPSecretManagerSource creates a CredentialSource backed by GCP Secret Manager.
func NewGCPSecretManagerSource(project, secret, version string) (CredentialSource, error) {
	client, err := newRealGCPSMClient()
	if err != nil {
		return nil, fmt.Errorf("creating GCP Secret Manager client: %w", err)
	}
	return newGCPSecretManagerSourceWithClient(project, secret, version, client), nil
}

func newGCPSecretManagerSourceWithClient(project, secret, version string, client GCPSecretManagerClient) CredentialSource {
	if version == "" {
		version = "latest"
	}
	resourceName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", project, secret, version)
	return &gcpSMSource{resourceName: resourceName, client: client}
}

func (s *gcpSMSource) Fetch(ctx context.Context) (string, error) {
	return s.client.AccessSecretVersion(ctx, s.resourceName)
}

func (s *gcpSMSource) Type() string { return "gcp-secretmanager" }

// realGCPSMClient wraps the GCP Secret Manager client.
type realGCPSMClient struct {
	client *secretmanager.Client
}

func newRealGCPSMClient() (*realGCPSMClient, error) {
	client, err := secretmanager.NewClient(context.Background())
	if err != nil {
		return nil, err
	}
	return &realGCPSMClient{client: client}, nil
}

func (c *realGCPSMClient) AccessSecretVersion(ctx context.Context, resourceName string) (string, error) {
	resp, err := c.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: resourceName,
	})
	if err != nil {
		return "", err
	}
	if resp.Payload == nil || resp.Payload.Data == nil {
		return "", fmt.Errorf("secret %s has no payload data", resourceName)
	}
	return string(resp.Payload.Data), nil
}
