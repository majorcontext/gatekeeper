package credentialsource

import (
	"fmt"
	"strings"
)

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
