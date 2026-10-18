package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/xxxsen/atlas/internal/bootstrap"
)

func newBootstrapCommand(now func() time.Time) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Generate keys, sign and verify bootstrap TXT records offline",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newKeygenCommand(), newSignCommand(now), newVerifyCommand(now))
	return cmd
}

func newKeygenCommand() *cobra.Command {
	var privatePath, publicPath string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 key pair without overwriting existing files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			privateDER, err := x509.MarshalPKCS8PrivateKey(private)
			if err != nil {
				return err
			}
			publicDER, err := x509.MarshalPKIXPublicKey(public)
			if err != nil {
				return err
			}
			if err := writeKeyFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
				return err
			}
			if err := writeKeyFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
				_ = os.Remove(privatePath)
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "public key ID: %s\nprivate key: %s\npublic key: %s\n", bootstrap.KeyID(public), privatePath, publicPath)
			return err
		},
	}
	cmd.Flags().StringVar(&privatePath, "private-key", "", "output Ed25519 PKCS#8 PEM file (must not exist)")
	cmd.Flags().StringVar(&publicPath, "public-key", "", "output public PEM file (must not exist)")
	_ = cmd.MarkFlagRequired("private-key")
	_ = cmd.MarkFlagRequired("public-key")
	return cmd
}

func newSignCommand(now func() time.Time) *cobra.Command {
	var privatePath, domain string
	var expiresAt int64
	var a, aaaa []string
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign addresses and print the complete TXT value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := bootstrap.ReadPrivateKey(privatePath)
			if err != nil {
				return err
			}
			value, err := bootstrap.Sign(key, bootstrap.Record{
				Domain: domain, IssuedAt: now().UnixMilli(), ExpiresAt: expiresAt, A: a, AAAA: aaaa,
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), value)
			return err
		},
	}
	cmd.Flags().StringVar(&privatePath, "private-key", "", "Ed25519 private PEM file")
	cmd.Flags().StringVar(&domain, "domain", "", "exact domain to authorize")
	cmd.Flags().Int64Var(&expiresAt, "expires-at", 0, "required expiration as a Unix MILLISECOND timestamp; not a date or Unix seconds")
	cmd.Flags().StringArrayVar(&a, "a", nil, "IPv4 address; repeat for multiple addresses")
	cmd.Flags().StringArrayVar(&aaaa, "aaaa", nil, "IPv6 address; repeat for multiple addresses")
	_ = cmd.MarkFlagRequired("private-key")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("expires-at")
	return cmd
}

func newVerifyCommand(now func() time.Time) *cobra.Command {
	var publicPath, domain, wire string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a TXT value and print the validated record as JSON",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := bootstrap.ReadPublicKey(publicPath)
			if err != nil {
				return err
			}
			record, err := bootstrap.Verify(wire, domain, map[string]ed25519.PublicKey{bootstrap.KeyID(key): key}, now(), 30*time.Second)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(record)
		},
	}
	cmd.Flags().StringVar(&publicPath, "public-key", "", "trusted public PEM file")
	cmd.Flags().StringVar(&domain, "domain", "", "expected exact domain")
	cmd.Flags().StringVar(&wire, "record", "", "complete atlas1 TXT value")
	_ = cmd.MarkFlagRequired("public-key")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("record")
	return cmd
}

func writeKeyFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}
