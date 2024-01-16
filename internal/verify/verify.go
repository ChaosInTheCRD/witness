package verify

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/source"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/in-toto/witness/internal/util"
	"github.com/in-toto/witness/options"
)

func VerifyOpts(ctx context.Context, vo *options.VerifyOptions) ([]witness.VerifyOption, error) {
	roots, err := util.CertsFromFiles(vo.PolicyRoots)
	if err != nil {
		return nil, fmt.Errorf("failed to load root certificates: %w", err)
	}

	intermediates, err := util.CertsFromFiles(vo.PolicyIntermediates)
	if err != nil {
		return nil, fmt.Errorf("failed to load intermediate certificates: %w", err)
	}

	timestampers := make([]timestamp.Timestamper, 0)
	if len(vo.PolicyTSARoots) > 0 {
		roots, err := util.CertsFromFiles(vo.PolicyTSARoots)
		if err != nil {
			return nil, fmt.Errorf("failed to load timestamp authority root certificates: %w", err)
		}

		for _, root := range roots {
			timestampers = append(timestampers, timestamp.NewTimestampAuthority(timestamp.VerifyWithCertChain([]*x509.Certificate{root})))
		}
	}

	subjects, err := subjectsFromOpts(ctx, vo)
	if err != nil {
		return nil, err
	}

	collectionSource, err := collectionSourceFromOpts(ctx, vo)
	if err != nil {
		return nil, err
	}

	return []witness.VerifyOption{
		witness.VerifyWithSubjectDigests(subjects),
		witness.VerifyWithCollectionSource(collectionSource),
		witness.VerifyWithPolicyRoots(roots),
		witness.VerifyWithPolicyIntermediates(intermediates),
		witness.VerifyWithPolicyTimestampers(timestampers),
	}, nil
}

// VerifiersFromOpts creates and returns the subject digest set from the verify options.
func VerifiersFromOpts(ctx context.Context, vo *options.VerifyOptions) ([]cryptoutil.Verifier, error) {
	if vo.KeyPath == "" && len(vo.PolicyRoots) == 0 {
		return nil, fmt.Errorf("must supply public key or ca paths")
	}

	verifiers := make([]cryptoutil.Verifier, 0)
	if vo.KeyPath != "" {
		keyFile, err := os.Open(vo.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open key file: %w", err)
		}
		defer keyFile.Close()

		v, err := cryptoutil.NewVerifierFromReader(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier: %w", err)
		}

		verifiers = append(verifiers, v)
	}

	return verifiers, nil
}

// subjectsFromOpts creates and returns the subject digest set from the verify options.
func subjectsFromOpts(ctx context.Context, vo *options.VerifyOptions) ([]cryptoutil.DigestSet, error) {
	subjects := []cryptoutil.DigestSet{}
	if len(vo.ArtifactFilePath) > 0 {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []crypto.Hash{crypto.SHA256})
		if err != nil {
			return nil, fmt.Errorf("failed to calculate artifact digest: %w", err)
		}
		subjects = append(subjects, artifactDigestSet)
	}

	for _, subDigest := range vo.AdditionalSubjects {
		subjects = append(subjects, cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: subDigest})
	}

	if len(subjects) == 0 {
		return nil, errors.New("at least one subject is required, provide an artifact file or subject")
	}
	return subjects, nil
}

func collectionSourceFromOpts(ctx context.Context, vo *options.VerifyOptions) (source.Sourcer, error) {
	var collectionSource source.Sourcer
	memSource := source.NewMemorySource()
	for _, path := range vo.AttestationFilePaths {
		if err := memSource.LoadFile(path); err != nil {
			return nil, fmt.Errorf("failed to load attestation file: %w", err)
		}
	}

	collectionSource = memSource
	if vo.ArchivistaOptions.Enable {
		collectionSource = source.NewMultiSource(collectionSource, source.NewArchvistSource(archivista.New(vo.ArchivistaOptions.Url)))
	}

	return collectionSource, nil
}
