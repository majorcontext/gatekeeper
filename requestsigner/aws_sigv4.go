// Package requestsigner provides per-request signing mechanisms for outbound
// HTTP requests. Unlike credentialsource (which fetches a static value once),
// request signers operate on the full HTTP request at proxy time.
package requestsigner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// AWSSigV4Signer signs outbound HTTP requests with AWS Signature Version 4.
type AWSSigV4Signer struct {
	signer  *v4.Signer
	creds   aws.CredentialsProvider
	region  string
	service string
}

// NewAWSSigV4Signer creates a signer that uses the default AWS credential chain
// (env vars, shared config, IMDS, etc.).
func NewAWSSigV4Signer(region, service string) (*AWSSigV4Signer, error) {
	if region == "" {
		return nil, fmt.Errorf("aws-sigv4: region is required")
	}
	if service == "" {
		return nil, fmt.Errorf("aws-sigv4: service is required")
	}

	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("aws-sigv4: loading AWS config: %w", err)
	}

	return &AWSSigV4Signer{
		signer:  v4.NewSigner(),
		creds:   cfg.Credentials,
		region:  region,
		service: service,
	}, nil
}

// NewAWSSigV4SignerWithStaticCredentials creates a signer using explicit keys.
func NewAWSSigV4SignerWithStaticCredentials(accessKeyID, secretAccessKey, region, service string) (*AWSSigV4Signer, error) {
	if region == "" {
		return nil, fmt.Errorf("aws-sigv4: region is required")
	}
	if service == "" {
		return nil, fmt.Errorf("aws-sigv4: service is required")
	}

	provider := aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
		}, nil
	})

	return &AWSSigV4Signer{
		signer:  v4.NewSigner(),
		creds:   provider,
		region:  region,
		service: service,
	}, nil
}

const unsignedPayload = "UNSIGNED-PAYLOAD"

// SignRequest signs an HTTP request with SigV4 in place.
// For bodies <=1MB, the payload is hashed for a full signature.
// Larger or unknown-length bodies use UNSIGNED-PAYLOAD.
func (s *AWSSigV4Signer) SignRequest(ctx context.Context, req *http.Request) error {
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("aws-sigv4: retrieving credentials: %w", err)
	}

	payloadHash := unsignedPayload
	if req.Body != nil && req.ContentLength >= 0 && req.ContentLength <= 1<<20 {
		body, readErr := io.ReadAll(req.Body)
		req.Body.Close()
		if readErr != nil {
			return fmt.Errorf("aws-sigv4: reading request body: %w", readErr)
		}
		h := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(h[:])
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}

	return s.signer.SignHTTP(ctx, creds, req, payloadHash, s.service, s.region, time.Now())
}
