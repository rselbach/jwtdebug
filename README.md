# jwtdebug

A simple command-line utility for decoding and debugging JSON Web Tokens (JWTs).

```bash
# Install via Homebrew
brew install rselbach/tap/jwtdebug

# Try it now with this sample token:
jwtdebug eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# Decode a token
jwtdebug eyJhbGciOiJIUzI1NiIs...

# Decode from clipboard (macOS)
pbpaste | jwtdebug

# Show everything
jwtdebug -a eyJhbGciOiJIUzI1NiIs...

# Verify signature with an explicitly trusted algorithm
jwtdebug -V -k public.pem --algorithm RS256 eyJhbGciOiJIUzI1NiIs...

# Pipe claims to jq
jwtdebug --raw-claims token | jq '.sub'
```
