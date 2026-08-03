package jwtdebug

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSupportedAlgorithmsVerify(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-521 key: %v", err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	tests := map[string]struct {
		privateKey any
		publicKey  any
		keyData    []byte
	}{
		"HS256": {privateKey: []byte(strings.Repeat("a", 32)), keyData: []byte(strings.Repeat("a", 32))},
		"HS384": {privateKey: []byte(strings.Repeat("b", 48)), keyData: []byte(strings.Repeat("b", 48))},
		"HS512": {privateKey: []byte(strings.Repeat("c", 64)), keyData: []byte(strings.Repeat("c", 64))},
		"RS256": {privateKey: rsaKey, publicKey: &rsaKey.PublicKey},
		"RS384": {privateKey: rsaKey, publicKey: &rsaKey.PublicKey},
		"RS512": {privateKey: rsaKey, publicKey: &rsaKey.PublicKey},
		"PS256": {privateKey: rsaKey, publicKey: &rsaKey.PublicKey},
		"PS384": {privateKey: rsaKey, publicKey: &rsaKey.PublicKey},
		"PS512": {privateKey: rsaKey, publicKey: &rsaKey.PublicKey},
		"ES256": {privateKey: p256Key, publicKey: &p256Key.PublicKey},
		"ES384": {privateKey: p384Key, publicKey: &p384Key.PublicKey},
		"ES512": {privateKey: p521Key, publicKey: &p521Key.PublicKey},
		"EdDSA": {privateKey: edPrivate, publicKey: edPublic},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			keyData := tc.keyData
			if keyData == nil {
				keyData = publicKeyPEM(t, tc.publicKey)
			}
			keyFile := writeTestKey(t, keyData)
			token := signedJWT(t, name, tc.privateKey, map[string]any{"sub": name})
			result := runCLI(t, []string{
				"--verify",
				"--algorithm", name,
				"--key-file", keyFile,
				token,
			}, "")
			if result.exitCode != exitSuccess {
				t.Fatalf("exit code = %d, stderr: %s", result.exitCode, result.stderr)
			}
			if !strings.Contains(result.stdout, "Signature verified successfully") ||
				!strings.Contains(result.stdout, name) {
				t.Fatalf("unexpected stdout: %s", result.stdout)
			}
		})
	}
}

func TestHMACVerificationFailures(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-bytes-long!")
	token := hmacJWT(t, secret, map[string]any{"sub": "Ben Chang"})

	tests := map[string]struct {
		keyData []byte
		want    string
	}{
		"wrong secret": {
			keyData: []byte("wrong-secret-key-at-least-32-bytes!!!!!"),
			want:    "signature is invalid",
		},
		"trailing newline": {
			keyData: append(append([]byte(nil), secret...), '\n'),
			want:    "key file ends with a newline",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := runCLI(t, []string{
				"--verify",
				"--algorithm", "HS256",
				"--key-file", writeTestKey(t, tc.keyData),
				token,
			}, "")
			if result.exitCode != exitVerificationFail || !strings.Contains(result.stderr, tc.want) {
				t.Fatalf("verification result: %+v", result)
			}
		})
	}
}

func TestVerifierConfigurationFailures(t *testing.T) {
	token := unsignedJWT(t, map[string]any{"sub": "Missing Configuration"})
	validKey := writeTestKey(t, []byte(strings.Repeat("x", 32)))

	tests := map[string]struct {
		args []string
		want string
	}{
		"missing key file option": {
			args: []string{"--verify", token},
			want: "key file not provided (--key-file / -k required)",
		},
		"missing expected algorithm": {
			args: []string{"--verify", "--key-file", validKey, token},
			want: "expected signing algorithm not provided (--algorithm required)",
		},
		"missing key path": {
			args: []string{"--verify", "--algorithm", "HS256", "--key-file", validKey + ".missing", token},
			want: "failed to open key file",
		},
		"directory key path": {
			args: []string{"--verify", "--algorithm", "HS256", "--key-file", t.TempDir(), token},
			want: "key file must be a regular file",
		},
		"unsupported algorithm": {
			args: []string{"--verify", "--algorithm", "none", "--key-file", validKey, token},
			want: "unexpected signing method: none",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := runCLI(t, tc.args, "")
			if result.exitCode != exitVerificationFail || !strings.Contains(result.stderr, tc.want) {
				t.Fatalf("result = %+v, want error containing %q", result, tc.want)
			}
		})
	}
}

func TestOversizedKeyFileIsRejected(t *testing.T) {
	keyFile := writeTestKey(t, []byte(strings.Repeat("x", maxKeyFileSize+1)))
	token := unsignedJWT(t, map[string]any{"sub": "Oversized Key"})
	result := runCLI(t, []string{
		"--verify", "--algorithm", "HS256", "--key-file", keyFile, token,
	}, "")
	if result.exitCode != exitVerificationFail || !strings.Contains(result.stderr, "key file too large") {
		t.Fatalf("result = %+v", result)
	}
}

func TestAsymmetricKeysCannotBeHMACSecrets(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pemData := publicKeyPEM(t, &rsaKey.PublicKey)
	derData, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal DER public key: %v", err)
	}

	for name, keyData := range map[string][]byte{"PEM": pemData, "DER": derData} {
		t.Run(name, func(t *testing.T) {
			token := hmacJWT(t, keyData, map[string]any{"sub": "Forged Human Being"})
			result := runCLI(t, []string{
				"--verify", "--algorithm", "HS256",
				"--key-file", writeTestKey(t, keyData),
				token,
			}, "")
			if result.exitCode != exitVerificationFail ||
				!strings.Contains(result.stderr, "HMAC key file contains an asymmetric key") {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestExpectedAlgorithmBlocksConfusion(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	publicKey := publicKeyPEM(t, &rsaKey.PublicKey)
	token := hmacJWT(t, publicKey, map[string]any{"sub": "Forged Human Being"})
	result := runCLI(t, []string{
		"--verify", "--algorithm", "RS256",
		"--key-file", writeTestKey(t, publicKey),
		token,
	}, "")
	if result.exitCode != exitVerificationFail ||
		!strings.Contains(result.stderr, "token signing algorithm HS256 does not match expected algorithm RS256") {
		t.Fatalf("result = %+v", result)
	}
}

func TestUnsupportedProtectedHeadersFailVerification(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-bytes-long!")
	keyFile := writeTestKey(t, secret)
	payload := base64.RawURLEncoding.EncodeToString(marshalTestJSON(t, map[string]any{
		"sub": "Misinterpreted Payload",
	}))

	tests := map[string]struct {
		header map[string]any
		want   string
	}{
		"unencoded payload": {
			header: map[string]any{"alg": "HS256", "b64": false, "crit": []string{"b64"}},
			want:   "unsupported b64 header",
		},
		"malformed b64": {
			header: map[string]any{"alg": "HS256", "b64": "false"},
			want:   "invalid b64 header",
		},
		"unknown critical parameter": {
			header: map[string]any{"alg": "HS256", "crit": []string{"example"}, "example": true},
			want:   "unsupported critical header parameters",
		},
		"malformed critical parameter": {
			header: map[string]any{"alg": "HS256", "crit": "example"},
			want:   "unsupported critical header parameters",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			header := base64.RawURLEncoding.EncodeToString(marshalTestJSON(t, tc.header))
			signingInput := header + "." + payload
			mac := hmac.New(sha256.New, secret)
			if _, err := mac.Write([]byte(signingInput)); err != nil {
				t.Fatalf("sign token: %v", err)
			}
			token := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

			result := runCLI(t, []string{
				"--verify", "--algorithm", "HS256", "--key-file", keyFile, token,
			}, "")
			if result.exitCode != exitVerificationFail || !strings.Contains(result.stderr, tc.want) {
				t.Fatalf("result = %+v, want error containing %q", result, tc.want)
			}
			if strings.Contains(result.stdout, "Misinterpreted Payload") ||
				strings.Contains(result.stdout, "Signature verified successfully") {
				t.Fatalf("verification emitted trusted output: %q", result.stdout)
			}
		})
	}
}

func TestUndersizedRSAKeysAreRejected(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	keyFile := writeTestKey(t, publicKeyPEM(t, &privateKey.PublicKey))

	for _, algorithm := range []string{"RS256", "PS256"} {
		t.Run(algorithm, func(t *testing.T) {
			token := signedJWT(t, algorithm, privateKey, map[string]any{"sub": algorithm})
			result := runCLI(t, []string{
				"--verify", "--algorithm", algorithm, "--key-file", keyFile, token,
			}, "")
			if result.exitCode != exitVerificationFail ||
				!strings.Contains(result.stderr, "RSA modulus must be at least 2048 bits") {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestShortHMACKeyWarnsOnceAndVerifiesEveryToken(t *testing.T) {
	secret := []byte("too-short")
	token := hmacJWT(t, secret, map[string]any{"sub": "Short HMAC Key"})
	result := runCLI(t, []string{
		"--verify", "--algorithm", "HS256",
		"--key-file", writeTestKey(t, secret),
		token, token,
	}, "")
	if result.exitCode != exitSuccess {
		t.Fatalf("result = %+v", result)
	}
	if got := strings.Count(result.stderr, "Warning: HMAC key is 9 bytes"); got != 1 {
		t.Fatalf("warning count = %d, stderr: %s", got, result.stderr)
	}
	if got := strings.Count(result.stdout, "Signature verified successfully"); got != 2 {
		t.Fatalf("success count = %d, stdout: %s", got, result.stdout)
	}
}

func TestJWTIOSampleVerifies(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	result := runCLI(t, []string{
		"--verify", "--algorithm", "HS256",
		"--key-file", writeTestKey(t, []byte("your-256-bit-secret")),
		token,
	}, "")
	if result.exitCode != exitSuccess {
		t.Fatalf("result = %+v", result)
	}
}

func TestVerificationTimeClaims(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-bytes-long!")
	keyFile := writeTestKey(t, secret)
	now := time.Now().Unix()

	tests := map[string]struct {
		claims           map[string]any
		ignoreExpiration bool
		wantCode         int
		wantError        string
	}{
		"audience is accepted": {
			claims:   map[string]any{"sub": "Troy Barnes", "aud": "greendale-community-college"},
			wantCode: exitSuccess,
		},
		"expired": {
			claims:    map[string]any{"sub": "Expired HMAC", "exp": now - 3600},
			wantCode:  exitVerificationFail,
			wantError: "token is expired",
		},
		"expired ignored": {
			claims:           map[string]any{"sub": "Expired HMAC", "exp": now - 3600},
			ignoreExpiration: true,
			wantCode:         exitSuccess,
		},
		"maximum unsigned expiration": {
			claims:   map[string]any{"sub": "Troy Barnes", "exp": json.Number("18446744073709551615")},
			wantCode: exitSuccess,
		},
		"fractional string expiration": {
			claims:    map[string]any{"sub": "Fractional String Exp", "exp": "1000000000.5"},
			wantCode:  exitVerificationFail,
			wantError: "token is expired",
		},
		"future string not-before": {
			claims:    map[string]any{"sub": "String NBF", "nbf": "2000000000"},
			wantCode:  exitVerificationFail,
			wantError: "token is not valid yet",
		},
		"ignored expiration still enforces not-before": {
			claims:           map[string]any{"sub": "Annie Edison", "exp": 1, "nbf": "2000000000"},
			ignoreExpiration: true,
			wantCode:         exitVerificationFail,
			wantError:        "token is not valid yet",
		},
		"malformed expiration": {
			claims:    map[string]any{"sub": "Bad Exp", "exp": true},
			wantCode:  exitVerificationFail,
			wantError: "invalid exp claim",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			token := hmacJWT(t, secret, tc.claims)
			args := []string{"--verify", "--algorithm", "HS256", "--key-file", keyFile}
			if tc.ignoreExpiration {
				args = append(args, "--ignore-expiration")
			}
			args = append(args, token)
			result := runCLI(t, args, "")
			if result.exitCode != tc.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr: %s", result.exitCode, tc.wantCode, result.stderr)
			}
			if tc.wantError != "" && !strings.Contains(result.stderr, tc.wantError) {
				t.Fatalf("stderr missing %q: %s", tc.wantError, result.stderr)
			}
		})
	}
}

func TestValidateTimeClaimsAtLeewayBoundary(t *testing.T) {
	now := time.Unix(1_700_000_000, 500_000_000)
	tests := map[string]struct {
		claims map[string]any
		want   string
	}{
		"fractional expiration below boundary": {
			claims: map[string]any{"exp": json.Number("1699999939.6")},
			want:   "token is expired",
		},
		"integer expiration at subsecond boundary": {
			claims: map[string]any{"exp": json.Number("1699999940")},
			want:   "token is expired",
		},
		"fractional not-before above boundary": {
			claims: map[string]any{"nbf": json.Number("1700000060.6")},
			want:   "token is not valid yet",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateTimeClaimsAt(tc.claims, now, false)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMissingTokenAlgorithmFails(t *testing.T) {
	secret := []byte(strings.Repeat("x", 32))
	token := tokenForParts(t, map[string]any{"typ": "JWT"}, map[string]any{"sub": "Missing Algorithm"}, nil)
	result := runCLI(t, []string{
		"--verify", "--algorithm", "HS256",
		"--key-file", writeTestKey(t, secret),
		token,
	}, "")
	if result.exitCode != exitVerificationFail || !strings.Contains(result.stderr, "unexpected signing method: <missing>") {
		t.Fatalf("result = %+v", result)
	}
}

func TestES512ErrorsNameParsingStage(t *testing.T) {
	invalidKey := runCLI(t, []string{
		"--verify", "--algorithm", "ES512",
		"--key-file", writeTestKey(t, []byte("not a public key")),
		unsignedJWT(t, map[string]any{"sub": "ES512 Key Parser"}),
	}, "")
	if invalidKey.exitCode != exitVerificationFail ||
		!strings.Contains(invalidKey.stderr, "failed to parse ES512 public key") {
		t.Fatalf("invalid key result = %+v", invalidKey)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-521 key: %v", err)
	}
	malformedSignature := tokenForParts(
		t,
		map[string]any{"alg": "ES512", "typ": "JWT"},
		map[string]any{"sub": "ES512 Signature Parser"},
		nil,
	)
	result := runCLI(t, []string{
		"--verify", "--algorithm", "ES512",
		"--key-file", writeTestKey(t, publicKeyPEM(t, &privateKey.PublicKey)),
		malformedSignature,
	}, "")
	if result.exitCode != exitVerificationFail ||
		!strings.Contains(result.stderr, "failed to parse ES512 signature") {
		t.Fatalf("malformed signature result = %+v", result)
	}
}

func TestVerifiedRawClaimsRemainEmptyOnFailure(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-bytes-long!")
	token := hmacJWT(t, secret, map[string]any{"sub": "Verified Raw Claims"})
	result := runCLI(t, []string{
		"--raw-claims", "--verify", "--algorithm", "HS256",
		"--key-file", writeTestKey(t, []byte("wrong-secret-key-at-least-32-bytes!!")),
		token,
	}, "")
	if result.exitCode != exitVerificationFail || result.stdout != "" {
		t.Fatalf("result = %+v", result)
	}
}

func TestKeyFileMustRemainRegularAfterOpen(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "key")
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close key file: %v", err)
	}
	if _, err := readKeyFile(file.Name()); err != nil {
		t.Fatalf("read regular key file: %v", err)
	}
}
