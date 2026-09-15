package scanner

import (
	"errors"
	"fmt"
	"strings"
)

// ErrPhaseBlocked marks a capability that could not be attempted because a
// required dependency or operator-supplied prerequisite was unavailable. The
// scheduler records it as a visible, terminal `blocked` phase while allowing
// independent modules to continue. It must never be interpreted as a clean
// negative result.
var ErrPhaseBlocked = errors.New("phase blocked")

func BlockedPhase(reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "required prerequisite is unavailable"
	}
	return fmt.Errorf("%w: %s", ErrPhaseBlocked, reason)
}

func IsPhaseBlocked(err error) bool { return errors.Is(err, ErrPhaseBlocked) }
