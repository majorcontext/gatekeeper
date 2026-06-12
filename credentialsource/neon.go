package credentialsource

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultNeonBaseURL is the production Neon API base URL.
const DefaultNeonBaseURL = "https://console.neon.tech"

const defaultNeonPasswordTTL = 5 * time.Minute

// ParseNeonEndpointID extracts the Neon endpoint ID from a hostname like
// "ep-cool-darkness-123456.us-east-2.aws.neon.tech". The "-pooler" suffix
// (connection pooler endpoints) is stripped.
func ParseNeonEndpointID(host string) (string, error) {
	label, _, _ := strings.Cut(host, ".")
	label = strings.TrimSuffix(label, "-pooler")
	if !strings.HasPrefix(label, "ep-") {
		return "", fmt.Errorf("host %q is not a neon endpoint hostname", host)
	}
	return label, nil
}

// NeonResolver resolves Postgres passwords for Neon endpoints via the Neon
// API. It maps an (endpoint hostname, role, database) tuple to a password by
// locating the project that owns the endpoint and fetching its connection
// URI. Resolved passwords are cached for TTL; endpoint-to-project/branch
// mappings are cached until InvalidatePassword drops them (Neon can reassign
// an endpoint to a different branch).
//
// The zero value is not usable: APIKey must be set. All other fields are
// optional. NeonResolver is safe for concurrent use.
type NeonResolver struct {
	APIKey CredentialSource // source for the Neon API key
	// Project is an optional Neon project ID. When set, the resolver queries
	// this project directly instead of enumerating all projects — required for
	// project-scoped API keys, which cannot list projects.
	Project    string
	BaseURL    string        // defaults to DefaultNeonBaseURL
	TTL        time.Duration // password cache TTL; defaults to 5 minutes
	HTTPClient *http.Client  // defaults to a client with a 15s timeout

	mu        sync.Mutex
	passwords map[string]neonCachedPassword
	endpoints map[string]neonEndpointInfo
	// endpointsGen increments on every InvalidatePassword. A goroutine that
	// resolved an endpoint while a concurrent invalidation occurred must not
	// write its now-stale result back into the cache (see ResolvePassword).
	endpointsGen uint64
}

type neonCachedPassword struct {
	password  string
	expiresAt time.Time
}

type neonEndpointInfo struct {
	projectID string
	branchID  string
	expiresAt time.Time
}

// Type returns the resolver type identifier.
func (r *NeonResolver) Type() string { return "neon" }

// ResolvePassword returns the Postgres password for the given role and
// database on the Neon endpoint identified by host (e.g.
// "ep-cool-darkness-123456.us-east-2.aws.neon.tech"). Host comparison is
// case-insensitive since SNI values are case-insensitive.
func (r *NeonResolver) ResolvePassword(ctx context.Context, host, user, database string) (string, error) {
	host = strings.ToLower(host)
	endpointID, err := ParseNeonEndpointID(host)
	if err != nil {
		return "", err
	}
	cacheKey := neonPasswordKey(endpointID, user, database)

	ttl := r.TTL
	if ttl <= 0 {
		ttl = defaultNeonPasswordTTL
	}

	r.mu.Lock()
	if cached, ok := r.passwords[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		r.mu.Unlock()
		return cached.password, nil
	}
	info, haveInfo := r.endpoints[endpointID]
	// Expire endpoint info on the same TTL as passwords. Without this, a stale
	// branchID outlives its branch whenever a branch is deleted without first
	// causing an upstream auth failure (the only trigger for InvalidatePassword):
	// fetchPassword would keep hitting the gone branch and 404 — a non-auth error
	// connectWithRetry never retries — failing every connection until restart.
	if haveInfo && !time.Now().Before(info.expiresAt) {
		delete(r.endpoints, endpointID)
		haveInfo = false
	}
	gen := r.endpointsGen
	r.mu.Unlock()

	if !haveInfo {
		info, err = r.findEndpoint(ctx, endpointID)
		if err != nil {
			return "", err
		}
		info.expiresAt = time.Now().Add(ttl)
		r.mu.Lock()
		if r.endpoints == nil {
			r.endpoints = make(map[string]neonEndpointInfo)
		}
		// Only cache the result if no InvalidatePassword ran while findEndpoint
		// was in flight. Otherwise this result may predate a branch move, and
		// writing it would re-stale the cache after the invalidation meant to
		// clear it — defeating connectWithRetry's single retry.
		if r.endpointsGen == gen {
			r.endpoints[endpointID] = info
		}
		r.mu.Unlock()
	}

	password, err := r.fetchPassword(ctx, info, user, database)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	if r.passwords == nil {
		r.passwords = make(map[string]neonCachedPassword)
	}
	// Only cache the password if no InvalidatePassword ran since we captured
	// gen. A goroutine that read endpoint info before an invalidation (the
	// haveInfo path) may have fetched against a stale branch; writing it here
	// would re-poison the entry the invalidation just cleared. The same guard
	// protects the endpoint cache above.
	if r.endpointsGen == gen {
		r.passwords[cacheKey] = neonCachedPassword{password: password, expiresAt: time.Now().Add(ttl)}
	}
	r.mu.Unlock()
	return password, nil
}

// InvalidatePassword drops the cached password for the given tuple, along
// with the endpoint's cached project/branch info (Neon can reassign a compute
// endpoint to a different branch, e.g. on branch reset). Callers invoke this
// when authentication fails and then retry once; the retry re-discovers the
// endpoint and fetches fresh credentials.
func (r *NeonResolver) InvalidatePassword(host, user, database string) {
	host = strings.ToLower(host)
	endpointID, err := ParseNeonEndpointID(host)
	if err != nil {
		return
	}
	r.mu.Lock()
	delete(r.passwords, neonPasswordKey(endpointID, user, database))
	delete(r.endpoints, endpointID)
	r.endpointsGen++
	r.mu.Unlock()
}

func neonPasswordKey(endpointID, user, database string) string {
	return endpointID + "\x00" + user + "\x00" + database
}

// findEndpoint locates the project and branch that own endpointID.
//
// When r.Project is set, it queries that project's endpoints directly — the
// only mode available to project-scoped API keys, which cannot list projects.
// Otherwise it enumerates the API key's projects and each project's endpoints
// (account-scoped keys).
func (r *NeonResolver) findEndpoint(ctx context.Context, endpointID string) (neonEndpointInfo, error) {
	if r.Project != "" {
		branchID, err := r.lookupEndpointInProject(ctx, r.Project, endpointID)
		if err != nil {
			return neonEndpointInfo{}, err
		}
		if branchID == "" {
			return neonEndpointInfo{}, fmt.Errorf("neon endpoint %q not found in configured project", endpointID)
		}
		return neonEndpointInfo{projectID: r.Project, branchID: branchID}, nil
	}

	var projects struct {
		Projects []struct {
			ID string `json:"id"`
		} `json:"projects"`
	}
	if err := r.apiGet(ctx, "/api/v2/projects", &projects); err != nil {
		return neonEndpointInfo{}, err
	}
	truncated := len(projects.Projects) >= 100
	if truncated {
		slog.Warn("neon projects list may be truncated; pagination is not implemented",
			"count", len(projects.Projects))
	}
	for _, p := range projects.Projects {
		branchID, err := r.lookupEndpointInProject(ctx, p.ID, endpointID)
		if err != nil {
			return neonEndpointInfo{}, err
		}
		if branchID != "" {
			return neonEndpointInfo{projectID: p.ID, branchID: branchID}, nil
		}
	}
	if truncated {
		// The endpoint may live in a project past the first (unpaginated) page.
		// Point the operator at the cause rather than letting it read as a
		// missing-credential error. Setting `project` on the credential avoids
		// enumeration entirely.
		return neonEndpointInfo{}, fmt.Errorf("neon endpoint %q not found; the projects list was truncated at %d entries (set the credential's project field)", endpointID, len(projects.Projects))
	}
	return neonEndpointInfo{}, fmt.Errorf("neon endpoint %q not found in any accessible project", endpointID)
}

// lookupEndpointInProject fetches projectID's endpoints and returns the branch
// ID of the endpoint matching endpointID. It returns an empty branch ID (no
// error) when the endpoint is absent, so the caller can keep searching other
// projects during enumeration.
func (r *NeonResolver) lookupEndpointInProject(ctx context.Context, projectID, endpointID string) (string, error) {
	var endpoints struct {
		Endpoints []struct {
			ID       string `json:"id"`
			BranchID string `json:"branch_id"`
		} `json:"endpoints"`
	}
	path := "/api/v2/projects/" + url.PathEscape(projectID) + "/endpoints"
	if err := r.apiGet(ctx, path, &endpoints); err != nil {
		return "", err
	}
	for _, ep := range endpoints.Endpoints {
		if ep.ID == endpointID {
			return ep.BranchID, nil
		}
	}
	return "", nil
}

// fetchPassword retrieves the connection URI for the endpoint's branch and
// extracts the password.
func (r *NeonResolver) fetchPassword(ctx context.Context, info neonEndpointInfo, user, database string) (string, error) {
	q := url.Values{
		"branch_id":     {info.branchID},
		"database_name": {database},
		"role_name":     {user},
	}
	path := "/api/v2/projects/" + url.PathEscape(info.projectID) + "/connection_uri"
	var result struct {
		URI string `json:"uri"`
	}
	if err := r.apiGet(ctx, path+"?"+q.Encode(), &result); err != nil {
		return "", err
	}
	// The URI contains the password; never include it in errors or logs.
	u, err := url.Parse(result.URI)
	if err != nil {
		return "", fmt.Errorf("neon connection URI for endpoint in project %s is not a valid URL", info.projectID)
	}
	password, ok := u.User.Password()
	if !ok || password == "" {
		return "", fmt.Errorf("neon connection URI for endpoint in project %s contains no password", info.projectID)
	}
	return password, nil
}

// apiGet performs an authenticated GET against the Neon API and decodes the
// JSON response into out. Error messages never include the API key or the
// response body (which may contain credentials).
func (r *NeonResolver) apiGet(ctx context.Context, pathAndQuery string, out any) error {
	apiKey, err := r.APIKey.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetch neon API key: %w", err)
	}
	baseURL := r.BaseURL
	if baseURL == "" {
		baseURL = DefaultNeonBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+pathAndQuery, nil)
	if err != nil {
		return fmt.Errorf("build neon API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("neon API request failed: %w", err)
	}
	defer resp.Body.Close()

	path, _, _ := strings.Cut(pathAndQuery, "?")
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("neon API %s returned status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		// Do not wrap the decode error: it could echo response body text.
		return fmt.Errorf("neon API %s returned malformed JSON", path)
	}
	return nil
}
