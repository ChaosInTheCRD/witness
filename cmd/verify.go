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
	"os"

	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/witness/internal/util"
	"github.com/in-toto/witness/internal/verify"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
)

func VerifyCmd() *cobra.Command {
	vo := options.VerifyOptions{}
	cmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verifies a witness policy",
		Long:              "Verifies a policy provided key source and exits with code 0 if verification succeeds",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			verifiers, err := verify.VerifiersFromOpts(cmd.Context(), &vo)
			if err != nil {
				return fmt.Errorf("failed to load verifiers: %w", err)
			}
			return runVerify(cmd.Context(), vo, verifiers...)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

const (
	MAX_DEPTH = 4
)

// todo: this logic should be broken out and moved to pkg/
// we need to abstract where keys are coming from, etc
func runVerify(ctx context.Context, vo options.VerifyOptions, verifiers ...cryptoutil.Verifier) error {
	f, err := os.ReadFile(vo.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	policyEnvelope := &dsse.Envelope{}
	// reusing this function to marshal the policy envelope. We don't want to push the policy to archivista and have set the option appropriately.
	err = util.WriteAttestation(ctx, f, policyEnvelope, &options.ArchivistaOptions{Enable: false})
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	opts, err := verify.VerifyOpts(ctx, &vo)
	if err != nil {
		return fmt.Errorf("failed to load verify options: %w", err)
	}

	verifiedEvidence, err := witness.Verify(
		ctx,
		*policyEnvelope,
		verifiers,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("failed to verify policy: %w", err)
	}

	log.Info("Verification succeeded")
	log.Info("Evidence:")
	num := 0
	for _, stepEvidence := range verifiedEvidence {
		for _, e := range stepEvidence {
			log.Info(fmt.Sprintf("%d: %s", num, e.Reference))
			num++
		}
	}

	return nil
}
