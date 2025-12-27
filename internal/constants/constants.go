package constants

const (
	// MaxFileSizeBytes is the maximum allowed size for config and key files (1MB).
	// This limit prevents DoS attacks via oversized files.
	MaxFileSizeBytes = 1024 * 1024
)

// Exit codes for the application
const (
	ExitSuccess          = 0 // Successful execution
	ExitError            = 1 // General error
	ExitInvalidToken     = 2 // Token parsing/format error
	ExitVerificationFail = 3 // Signature verification failed
	ExitConfigError      = 4 // Configuration error
)
