package app

import (
	"context"

	"github.com/airomhq/airom/internal/fix"
)

// The fix stage asks the package registries and OSV which version to move to.
// Unit tests must not depend on the network, or on what OSV says this week, so
// resolution is the identity here and fix.Resolve is tested on its own against
// a local server.
func init() {
	resolveTargets = func(_ context.Context, ts []fix.Target) []fix.Target { return ts }
}
