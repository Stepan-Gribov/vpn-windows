package transports

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/KindlyVPN/foundation/transports/internal/dnsttclient"
)

type DNSQueryBudget = dnsttclient.QueryBudget

func NewDNSQueryBudget(maxQPS int) *DNSQueryBudget { return dnsttclient.NewQueryBudget(maxQPS) }

// OpenDNSCarrier exposes a single authenticated DNS lane so an SSH pool can
// attach one SSH client to each lane instead of multiplexing everything onto
// whichever DNS lane happened to authenticate first.
func OpenDNSCarrier(ctx context.Context, config DNSConfig, budget *DNSQueryBudget, index int) (PoolSession, error) {
	key, err := hex.DecodeString(config.PublicKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid DNS public key")
	}
	resolvers := ResolverCandidates(nil, config.Resolvers)
	for i := 0; i < len(resolvers); i++ {
		resolver := resolvers[(index+i)%len(resolvers)]
		s, err := dnsttclient.OpenWithBudget(ctx, resolver, config.Domain, key, budget)
		if err == nil {
			return dnsSession{s}, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("no reachable recursive DNS tunnel")
}
