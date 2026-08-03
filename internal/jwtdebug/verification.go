package jwtdebug

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"strings"
	"time"
)

const (
	maxKeyFileSize = 1024 * 1024
	timeLeeway     = 60 * time.Second
)

type algorithmFamily uint8

const (
	hmacAlgorithm algorithmFamily = iota
	rsaAlgorithm
	rsaPSSAlgorithm
	ecdsaAlgorithm
	edDSAAlgorithm
)

type signingAlgorithm struct {
	name               string
	family             algorithmFamily
	hash               crypto.Hash
	newHash            func() hash.Hash
	ecdsaSignatureSize int
	minimumKeySize     int
}

type weakHMACKeyWarning struct {
	actual  int
	minimum int
}

type verifier struct {
	expectedAlgorithm string
	algorithm         signingAlgorithm
	key               any
	ignoreExpiration  bool
	trailingNewline   bool
	weakKeyWarning    *weakHMACKeyWarning
}

func newVerifier(keyFile, expectedAlgorithm string, ignoreExpiration bool) (*verifier, error) {
	if keyFile == "" {
		return nil, errors.New("key file not provided (--key-file / -k required)")
	}
	if expectedAlgorithm == "" {
		return nil, errors.New("expected signing algorithm not provided (--algorithm required)")
	}

	keyData, err := readKeyFile(keyFile)
	if err != nil {
		return nil, err
	}
	algorithm, err := lookupAlgorithm(expectedAlgorithm)
	if err != nil {
		return nil, err
	}
	key, warning, err := prepareVerificationKey(algorithm, keyData)
	if err != nil {
		return nil, err
	}

	return &verifier{
		expectedAlgorithm: expectedAlgorithm,
		algorithm:         algorithm,
		key:               key,
		ignoreExpiration:  ignoreExpiration,
		trailingNewline:   bytes.HasSuffix(keyData, []byte("\n")),
		weakKeyWarning:    warning,
	}, nil
}

func lookupAlgorithm(name string) (signingAlgorithm, error) {
	algorithms := map[string]signingAlgorithm{
		"HS256": {name: "HS256", family: hmacAlgorithm, hash: crypto.SHA256, newHash: sha256.New, minimumKeySize: 32},
		"HS384": {name: "HS384", family: hmacAlgorithm, hash: crypto.SHA384, newHash: sha512.New384, minimumKeySize: 48},
		"HS512": {name: "HS512", family: hmacAlgorithm, hash: crypto.SHA512, newHash: sha512.New, minimumKeySize: 64},
		"RS256": {name: "RS256", family: rsaAlgorithm, hash: crypto.SHA256, newHash: sha256.New},
		"RS384": {name: "RS384", family: rsaAlgorithm, hash: crypto.SHA384, newHash: sha512.New384},
		"RS512": {name: "RS512", family: rsaAlgorithm, hash: crypto.SHA512, newHash: sha512.New},
		"PS256": {name: "PS256", family: rsaPSSAlgorithm, hash: crypto.SHA256, newHash: sha256.New},
		"PS384": {name: "PS384", family: rsaPSSAlgorithm, hash: crypto.SHA384, newHash: sha512.New384},
		"PS512": {name: "PS512", family: rsaPSSAlgorithm, hash: crypto.SHA512, newHash: sha512.New},
		"ES256": {name: "ES256", family: ecdsaAlgorithm, hash: crypto.SHA256, newHash: sha256.New, ecdsaSignatureSize: 64},
		"ES384": {name: "ES384", family: ecdsaAlgorithm, hash: crypto.SHA384, newHash: sha512.New384, ecdsaSignatureSize: 96},
		"ES512": {name: "ES512", family: ecdsaAlgorithm, hash: crypto.SHA512, newHash: sha512.New, ecdsaSignatureSize: 132},
		"EdDSA": {name: "EdDSA", family: edDSAAlgorithm},
	}

	algorithm, ok := algorithms[name]
	if !ok {
		return signingAlgorithm{}, fmt.Errorf("unexpected signing method: %s", name)
	}
	return algorithm, nil
}

func prepareVerificationKey(
	algorithm signingAlgorithm,
	keyData []byte,
) (any, *weakHMACKeyWarning, error) {
	if algorithm.family == hmacAlgorithm {
		if isAsymmetricKey(keyData) {
			return nil, nil, errors.New("HMAC key file contains an asymmetric key")
		}
		var warning *weakHMACKeyWarning
		if len(keyData) < algorithm.minimumKeySize {
			warning = &weakHMACKeyWarning{
				actual:  len(keyData),
				minimum: algorithm.minimumKeySize,
			}
		}
		return keyData, warning, nil
	}

	publicKey, err := parsePublicKeyPEM(keyData)
	if err != nil {
		if algorithm.name == "ES512" {
			return nil, nil, fmt.Errorf("failed to parse ES512 public key: %w", err)
		}
		return nil, nil, fmt.Errorf("failed to parse %s public key: %w", algorithm.name, err)
	}

	switch algorithm.family {
	case rsaAlgorithm, rsaPSSAlgorithm:
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("failed to parse %s public key: expected RSA key", algorithm.name)
		}
		if key.N == nil || key.N.BitLen() < 2048 {
			return nil, nil, fmt.Errorf(
				"failed to parse %s public key: RSA modulus must be at least 2048 bits",
				algorithm.name,
			)
		}
		return key, nil, nil
	case ecdsaAlgorithm:
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("failed to parse %s public key: expected EC key", algorithm.name)
		}
		expectedBits := algorithm.ecdsaSignatureSize * 4
		if algorithm.name == "ES512" {
			expectedBits = 521
		}
		if key.Curve.Params().BitSize != expectedBits {
			return nil, nil, fmt.Errorf(
				"failed to parse %s public key: expected P-%d curve",
				algorithm.name,
				expectedBits,
			)
		}
		return key, nil, nil
	case edDSAAlgorithm:
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return nil, nil, errors.New("failed to parse EdDSA public key: expected Ed25519 key")
		}
		return key, nil, nil
	default:
		return nil, nil, fmt.Errorf("unexpected signing method: %s", algorithm.name)
	}
}

func parsePublicKeyPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if certificate, err := x509.ParseCertificate(block.Bytes); err == nil {
		return certificate.PublicKey, nil
	}
	return nil, errors.New("unsupported public key format")
}

func isAsymmetricKey(data []byte) bool {
	if block, _ := pem.Decode(data); block != nil {
		if strings.Contains(block.Type, "KEY") || block.Type == "CERTIFICATE" {
			return true
		}
		return isDERAsymmetricKey(block.Bytes)
	}
	return isDERAsymmetricKey(data)
}

func isDERAsymmetricKey(data []byte) bool {
	if _, err := x509.ParsePKIXPublicKey(data); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return true
	}
	if _, err := x509.ParseCertificate(data); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(data); err == nil {
		return true
	}
	return false
}

func readKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("key file must be a regular file")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %w", err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil {
		closeErr := file.Close()
		return nil, fmt.Errorf("failed to open key file: %w", errors.Join(statErr, closeErr))
	}
	if !openedInfo.Mode().IsRegular() {
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		return nil, errors.New("key file must be a regular file")
	}

	data, readErr := io.ReadAll(io.LimitReader(file, maxKeyFileSize+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	if len(data) > maxKeyFileSize {
		return nil, fmt.Errorf("key file too large (max %d bytes)", maxKeyFileSize)
	}
	return data, nil
}

func (v *verifier) verify(token parsedToken, now time.Time) error {
	actualAlgorithm, ok := token.header["alg"].(string)
	if !ok {
		return errors.New("unexpected signing method: <missing>")
	}
	if actualAlgorithm != v.expectedAlgorithm {
		return fmt.Errorf(
			"token signing algorithm %s does not match expected algorithm %s",
			actualAlgorithm,
			v.expectedAlgorithm,
		)
	}
	if err := validateProtectedHeader(token.header); err != nil {
		return err
	}

	lastDot := strings.LastIndexByte(token.raw, '.')
	if lastDot < 0 {
		return errors.New("signature is invalid")
	}
	signingInput := []byte(token.raw[:lastDot])
	signature, err := decodeBase64URL(token.signature)
	if err != nil {
		return fmt.Errorf("failed to decode token signature: %w", err)
	}
	if err := v.verifySignature(signingInput, signature); err != nil {
		if v.algorithm.family == hmacAlgorithm && v.trailingNewline && errors.Is(err, errInvalidSignature) {
			return errors.New("signature is invalid (key file ends with a newline; if that is not part of the secret, write it with `printf %s` or `echo -n`)")
		}
		return err
	}

	return validateTimeClaimsAt(token.claims, now, v.ignoreExpiration)
}

func validateProtectedHeader(header map[string]any) error {
	if value, ok := header["b64"]; ok {
		encoded, ok := value.(bool)
		if !ok {
			return errors.New("invalid b64 header: expected a boolean")
		}
		if !encoded {
			return errors.New("unsupported b64 header: false is not valid for JWTs")
		}
	}
	if _, ok := header["crit"]; ok {
		return errors.New("unsupported critical header parameters")
	}
	return nil
}

var errInvalidSignature = errors.New("signature is invalid")

func (v *verifier) verifySignature(signingInput, signature []byte) error {
	switch v.algorithm.family {
	case hmacAlgorithm:
		mac := hmac.New(v.algorithm.newHash, v.key.([]byte))
		if _, err := mac.Write(signingInput); err != nil {
			return fmt.Errorf("failed to hash token: %w", err)
		}
		if !hmac.Equal(signature, mac.Sum(nil)) {
			return errInvalidSignature
		}
		return nil
	case rsaAlgorithm, rsaPSSAlgorithm, ecdsaAlgorithm:
		hasher := v.algorithm.newHash()
		if _, err := hasher.Write(signingInput); err != nil {
			return fmt.Errorf("failed to hash token: %w", err)
		}
		digest := hasher.Sum(nil)
		if v.algorithm.family == rsaAlgorithm {
			if err := rsa.VerifyPKCS1v15(v.key.(*rsa.PublicKey), v.algorithm.hash, digest, signature); err != nil {
				return errInvalidSignature
			}
			return nil
		}
		if v.algorithm.family == rsaPSSAlgorithm {
			err := rsa.VerifyPSS(
				v.key.(*rsa.PublicKey),
				v.algorithm.hash,
				digest,
				signature,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: v.algorithm.hash},
			)
			if err != nil {
				return errInvalidSignature
			}
			return nil
		}
		return v.verifyECDSA(digest, signature)
	case edDSAAlgorithm:
		if !ed25519.Verify(v.key.(ed25519.PublicKey), signingInput, signature) {
			return errInvalidSignature
		}
		return nil
	default:
		return fmt.Errorf("unexpected signing method: %s", v.algorithm.name)
	}
}

func (v *verifier) verifyECDSA(digest, signature []byte) error {
	if len(signature) != v.algorithm.ecdsaSignatureSize {
		if v.algorithm.name == "ES512" {
			return fmt.Errorf(
				"failed to parse ES512 signature: invalid signature length %d",
				len(signature),
			)
		}
		return errInvalidSignature
	}

	componentSize := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:componentSize])
	s := new(big.Int).SetBytes(signature[componentSize:])
	if !ecdsa.Verify(v.key.(*ecdsa.PublicKey), digest, r, s) {
		return errInvalidSignature
	}
	return nil
}

func validateTimeClaimsAt(claims map[string]any, now time.Time, ignoreExpiration bool) error {
	if !ignoreExpiration {
		expiration := classifyTimeClaim(claims, "exp")
		switch {
		case expiration.kind == timeClaimInvalid:
			return fmt.Errorf("invalid exp claim: %s", formatJSONValue(expiration.raw))
		case expiration.kind == timeClaimValid && expiration.value.isBefore(now.Add(-timeLeeway)):
			return errors.New("token is expired")
		}
	}

	notBefore := classifyTimeClaim(claims, "nbf")
	switch {
	case notBefore.kind == timeClaimInvalid:
		return fmt.Errorf("invalid nbf claim: %s", formatJSONValue(notBefore.raw))
	case notBefore.kind == timeClaimValid && notBefore.value.isAfter(now.Add(timeLeeway)):
		return errors.New("token is not valid yet")
	}
	return nil
}
