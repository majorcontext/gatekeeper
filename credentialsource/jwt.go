package credentialsource

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// signRS256JWT builds and signs a JWT over the given claims with the RS256
// algorithm.
func signRS256JWT(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
