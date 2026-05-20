package executor

import "github.com/pkg/errors"

// ValidContainerID validates that id is non-empty and contains only ASCII letters and digits.
// This prevents path traversal attacks where a malicious frontend could craft an id like
// "../../etc/passwd" to write files outside the BuildKit state directory.
func ValidContainerID(id string) error {
	if id == "" {
		return errors.New("container id must not be empty")
	}
	for i := range len(id) {
		ch := id[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}
		return errors.Errorf("invalid container id %q: only letters and numbers are allowed", id)
	}
	return nil
}
