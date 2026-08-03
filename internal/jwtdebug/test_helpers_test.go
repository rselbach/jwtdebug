package jwtdebug

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

type cliResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func runCLI(t *testing.T, args []string, stdin string) cliResult {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	out := newOutput(&stdout, &stderr)
	exitCode := run(args, bytes.NewBufferString(stdin), false, out)
	if err := out.finish(); err != nil {
		t.Fatalf("finish output: %v", err)
	}
	return cliResult{exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String()}
}

func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	return tokenForParts(t, map[string]any{"alg": "none", "typ": "JWT"}, claims, nil)
}

func hmacJWT(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()
	return signedJWT(t, "HS256", secret, claims)
}

func signedJWT(t *testing.T, algorithm string, privateKey any, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": algorithm, "typ": "JWT"}
	headerData := marshalTestJSON(t, header)
	claimsData := marshalTestJSON(t, claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerData) + "." +
		base64.RawURLEncoding.EncodeToString(claimsData)
	spec, err := lookupAlgorithm(algorithm)
	if err != nil {
		t.Fatalf("look up algorithm: %v", err)
	}

	var signature []byte
	switch spec.family {
	case hmacAlgorithm:
		mac := hmac.New(spec.newHash, privateKey.([]byte))
		if _, err := mac.Write([]byte(signingInput)); err != nil {
			t.Fatalf("sign HMAC token: %v", err)
		}
		signature = mac.Sum(nil)
	case rsaAlgorithm, rsaPSSAlgorithm, ecdsaAlgorithm:
		hasher := spec.newHash()
		if _, err := hasher.Write([]byte(signingInput)); err != nil {
			t.Fatalf("hash signing input: %v", err)
		}
		digest := hasher.Sum(nil)
		switch spec.family {
		case rsaAlgorithm:
			signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), spec.hash, digest)
		case rsaPSSAlgorithm:
			signature, err = rsa.SignPSS(
				rand.Reader,
				privateKey.(*rsa.PrivateKey),
				spec.hash,
				digest,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash},
			)
		case ecdsaAlgorithm:
			var r, s *big.Int
			r, s, err = ecdsa.Sign(rand.Reader, privateKey.(*ecdsa.PrivateKey), digest)
			if err == nil {
				componentSize := spec.ecdsaSignatureSize / 2
				signature = make([]byte, spec.ecdsaSignatureSize)
				r.FillBytes(signature[:componentSize])
				s.FillBytes(signature[componentSize:])
			}
		}
		if err != nil {
			t.Fatalf("sign %s token: %v", algorithm, err)
		}
	case edDSAAlgorithm:
		signature = ed25519.Sign(privateKey.(ed25519.PrivateKey), []byte(signingInput))
	default:
		t.Fatalf("unsupported signing family for %s", algorithm)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func tokenForParts(
	t *testing.T,
	header map[string]any,
	claims map[string]any,
	signature []byte,
) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(marshalTestJSON(t, header)) + "." +
		base64.RawURLEncoding.EncodeToString(marshalTestJSON(t, claims)) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
}

func marshalTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test JSON: %v", err)
	}
	return data
}

func writeTestKey(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "verification.key")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func publicKeyPEM(t *testing.T, publicKey any) []byte {
	t.Helper()
	data, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data})
}
