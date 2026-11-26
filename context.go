package authent

import "context"

type principalKey struct{}

// NewContext returns a copy of ctx that carries p. Transport adapters such
// as httpauth use it so that handlers can read the Principal with
// FromContext.
func NewContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the Principal stored in ctx by NewContext.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
