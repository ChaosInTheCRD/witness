package sign

import (
	"context"
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/in-toto/witness/options"
)

// SignOpts prepares and returns a slice of dsse.SignOption's to be used by the sign command when executing witness.Sign.
func SignOpts(ctx context.Context, so *options.SignOptions, signers ...cryptoutil.Signer) ([]dsse.SignOption, error) {
	if len(signers) > 1 {
		return nil, fmt.Errorf("only one signer is supported")
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no signers found")
	}

	timestampers := []timestamp.Timestamper{}
	for _, url := range so.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestampAuthority(timestamp.TimestampWithURL(url)))
	}

	return []dsse.SignOption{
		dsse.SignWithSigners(signers[0]),
		dsse.SignWithTimestampers(timestampers...),
	}, nil
}
