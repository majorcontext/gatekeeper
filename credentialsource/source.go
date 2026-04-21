package credentialsource

import (
	"context"
	"time"
)

// CredentialSource fetches a credential value from an external system.
type CredentialSource interface {
	Fetch(ctx context.Context) (string, error)
	Type() string
}

// RefreshingSource is a CredentialSource whose values expire and must be
// re-fetched periodically. TTL returns the duration until the most recently
// fetched credential expires. Callers use this to schedule background refresh.
type RefreshingSource interface {
	CredentialSource
	TTL() time.Duration
}
