package main

import (
	"strings"

	"github.com/docker/docker/pkg/idtools"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/sys/user"
	"github.com/pkg/errors"
)

// parseIdentityMapping resolves a userns-remap spec ("user[:group]") to an
// idtools.IdentityMapping. Upstream moby/moby v28.5.x relocated
// LoadIdentityMapping out of pkg/idtools and into github.com/moby/sys/user,
// returning the new user.IdentityMapping type. We call the relocated API
// and adapt with idtools.FromUserIdentityMapping to keep the rest of
// buildkit's idtools.IdentityMapping consumers unchanged.
func parseIdentityMapping(str string) (*idtools.IdentityMapping, error) {
	if str == "" {
		return nil, nil
	}

	idparts := strings.SplitN(str, ":", 3)
	if len(idparts) > 2 {
		return nil, errors.Errorf("invalid userns remap specification in %q", str)
	}

	username := idparts[0]

	bklog.L.Debugf("user namespaces: ID ranges will be mapped to subuid ranges of: %s", username)

	mappings, err := user.LoadIdentityMapping(username)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ID mappings")
	}
	idMap := idtools.FromUserIdentityMapping(mappings)
	return &idMap, nil
}
