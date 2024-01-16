// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"

	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/witness/internal/run"
	"github.com/in-toto/witness/internal/util"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
)

func RunCmd() *cobra.Command {
	o := options.RunOptions{
		AttestorOptSetters: make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		SignerOptions:      options.SignerOptions{},
	}

	cmd := &cobra.Command{
		Use:           "run [cmd]",
		Short:         "Runs the provided command and records attestations about the execution",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			signers, err := loadSigners(cmd.Context(), o.SignerOptions, signerProvidersFromFlags(cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signers")
			}

			return runRun(cmd.Context(), o, args, signers...)
		},
		Args: cobra.ArbitraryArgs,
	}

	o.AddFlags(cmd)
	return cmd
}

func runRun(ctx context.Context, ro options.RunOptions, args []string, signers ...cryptoutil.Signer) error {
	out, err := loadOutfile(ro.OutFilePath)
	if err != nil {
		return fmt.Errorf("failed to open out file: %w", err)
	}
	defer out.Close()

	opts, err := run.RunOpts(ctx, &ro, args, signers...)
	if err != nil {
		return fmt.Errorf("failed to create run options: %w", err)
	}

	result, err := witness.Run(
		ro.StepName,
		signers[0],
		opts...,
	)
	if err != nil {
		return err
	}

	if err := util.WriteAttestation(ctx, &result.SignedEnvelope, out, &ro.ArchivistaOptions); err != nil {
		return fmt.Errorf("failed to write envelope to out file: %w", err)
	}

	return nil
}
