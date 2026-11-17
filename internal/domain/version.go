package domain

import "context"

// DirectoryVersioner reads the monotonic directory generation
// (directory_version.version). Repository writes affecting the served
// LDAP tree bump it; readers compare before serving cached snapshots so
// invalidations work across processes.
type DirectoryVersioner interface {
	Current(ctx context.Context) (int64, error)
}
