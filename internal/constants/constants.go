package constants

const (
	// MaxFileSizeBytes is the maximum allowed size for config and key files (1MB).
	// This limit prevents DoS attacks via oversized files.
	MaxFileSizeBytes = 1024 * 1024
)
