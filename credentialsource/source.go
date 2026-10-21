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

// startupRetryWindow is how long a caller retries the failed first Fetch of
// a source that authenticates with ambient cloud credentials. The GKE
// metadata server can refuse requests for the first seconds of a new Pod.
const startupRetryWindow = 30 * time.Second

// RefreshingSource is a CredentialSource whose values expire and must be
// re-fetched periodically. TTL returns the duration until the most recently
// fetched credential expires. Callers use this to schedule background refresh.
type RefreshingSource interface {
	CredentialSource
	TTL() time.Duration
}
