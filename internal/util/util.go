package util

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/witness/options"
)

// WriteDataJSON Marshals the provided data as JSON and writes it to the provided writer.
func WriteAttestation(ctx context.Context, data interface{}, out io.Writer, ao *options.ArchivistaOptions) error {
	signedBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	if _, err := out.Write(signedBytes); err != nil {
		return fmt.Errorf("failed to write envelope to out file: %w", err)
	}

	if ao.Enable {
		dsse, ok := data.(dsse.Envelope)
		if !ok {
			// NOTE: Not sure if we should fail here or just log a warning.
			log.Warnf("Archivista enabled, but only DSSE envelope type is currently supported.")
		} else {
			archivistaClient := archivista.New(ao.Url)
			if gitoid, err := archivistaClient.Store(ctx, dsse); err != nil {
				return fmt.Errorf("failed to store artifact in archivista: %w", err)
			} else {
				log.Infof("Stored in archivista as %v\n", gitoid)
			}
		}

	}

	return nil
}

// GenHashes converts a slice of strings to a slice of crypto.Hash
func GenHashes(hashes []string) ([]crypto.Hash, error) {
	var out []crypto.Hash
	for _, hash := range hashes {
		hash, err := cryptoutil.HashFromString(hash)
		if err != nil {
			return nil, fmt.Errorf("failed to parse hash: %w", err)
		}
		out = append(out, hash)

	}

	return out, nil
}

func CertsFromFiles(certs []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, cert := range certs {
		f, err := os.ReadFile(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to open root certificate file: %w", err)
		}
		cert, err := cryptoutil.TryParseCertificate(f)
		if err != nil {
			return nil, fmt.Errorf("failed to parse root certificate: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}
