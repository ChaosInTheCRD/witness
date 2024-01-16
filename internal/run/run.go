package run

import (
	"context"
	"fmt"

	"github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/in-toto/witness/internal/util"
	"github.com/in-toto/witness/options"
)

// RunOpts prepares and returns a slice of witness.RunOptions to be used by the run command when executing witness.Run.
func RunOpts(ctx context.Context, ro *options.RunOptions, args []string, signers ...cryptoutil.Signer) ([]witness.RunOption, error) {
	if len(signers) > 1 {
		return nil, fmt.Errorf("only one signer is supported")
	} else if len(signers) == 0 {
		return nil, fmt.Errorf("no signers found")
	}

	timestampers := []timestamp.Timestamper{}
	for _, url := range ro.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestampAuthority(timestamp.TimestampWithURL(url)))
	}

	attestors, err := genAttestors(ro.Attestations, args)
	if err != nil {
		return nil, err
	}

	hashes, err := util.GenHashes(ro.Hashes)
	if err != nil {
		return nil, err
	}

	return []witness.RunOption{
		witness.RunWithAttestors(attestors),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(ro.WorkingDir), attestation.WithHashes(hashes)),
		witness.RunWithTimestampers(timestampers...),
	}, nil
}

func genAttestors(atts, args []string) ([]attestation.Attestor, error) {
	// NOTE: ATTESTORS NEED TO BE REPLACED BEFORE MERGE
	attestors := []attestation.Attestor{}

	// If an argument is provided this is a command that the user intends to be attested.
	if len(args) > 0 {
		attestors = append(attestors, commandrun.New(commandrun.WithCommand(args)))
	}
	addtlAttestors, err := attestation.Attestors(atts)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestors := %w", err)
	}
	attestors = append(attestors, addtlAttestors...)
	return attestors, nil
}
