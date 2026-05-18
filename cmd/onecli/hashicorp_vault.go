package main

import (
	"encoding/json"
	"fmt"

	"github.com/onecli/onecli-cli/internal/api"
	"github.com/onecli/onecli-cli/pkg/output"
	"github.com/onecli/onecli-cli/pkg/validate"
)

// HashicorpVaultCmd is the `onecli hashicorp-vault` command group.
type HashicorpVaultCmd struct {
	Mappings VaultMappingsCmd `cmd:"" help:"Manage HashiCorp Vault hostname mappings."`
	Paths    VaultPathsCmd    `cmd:"" help:"Browse HashiCorp Vault KV paths."`
	Secrets  VaultSecretsCmd  `cmd:"" help:"Inspect and write HashiCorp Vault secret fields."`
}

// VaultMappingsCmd is the `onecli hashicorp-vault mappings` command group.
type VaultMappingsCmd struct {
	List   VaultMappingsListCmd   `cmd:"" help:"List HashiCorp Vault hostname mappings."`
	Upsert VaultMappingsUpsertCmd `cmd:"" help:"Create or update a HashiCorp Vault hostname mapping."`
	Delete VaultMappingsDeleteCmd `cmd:"" help:"Delete a HashiCorp Vault hostname mapping."`
}

type VaultMappingsListCmd struct {
	Project string `optional:"" short:"p" help:"Project slug."`
	Fields  string `optional:"" help:"Comma-separated list of fields to include in output."`
	Quiet   string `optional:"" name:"quiet" help:"Output only the specified field, one per line."`
}

func (c *VaultMappingsListCmd) Run(out *output.Writer) error {
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	mappings, err := client.ListVaultMappings(newContext(), project)
	if err != nil {
		return err
	}
	if c.Quiet != "" {
		return out.WriteQuiet(mappings, c.Quiet)
	}
	return out.WriteFiltered(mappings, c.Fields)
}

type VaultMappingsUpsertCmd struct {
	Project       string `optional:"" short:"p" help:"Project slug."`
	Hostname      string `required:"" help:"Upstream hostname, e.g. api.openai.com."`
	Path          string `required:"" help:"Vault logical secret path."`
	Field         string `required:"" help:"Vault field containing the credential value."`
	UsernameField string `optional:"" name:"username-field" help:"Optional Vault field containing a username."`
	Json          string `optional:"" help:"Raw JSON payload. Overrides individual flags."`
	DryRun        bool   `optional:"" name:"dry-run" help:"Validate the request without executing it."`
}

func (c *VaultMappingsUpsertCmd) Run(out *output.Writer) error {
	input, err := vaultMappingInput(c.Json, c.Hostname, c.Path, c.Field, c.UsernameField)
	if err != nil {
		return err
	}
	if c.DryRun {
		return out.WriteDryRun("Would save HashiCorp Vault mapping", input)
	}
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	mappings, err := client.UpsertVaultMapping(newContext(), project, input)
	if err != nil {
		return err
	}
	return out.Write(mappings)
}

type VaultMappingsDeleteCmd struct {
	Project       string `optional:"" short:"p" help:"Project slug."`
	Hostname      string `required:"" help:"Upstream hostname, e.g. api.openai.com."`
	Path          string `required:"" help:"Vault logical secret path."`
	Field         string `required:"" help:"Vault field containing the credential value."`
	UsernameField string `optional:"" name:"username-field" help:"Optional Vault field containing a username."`
	Json          string `optional:"" help:"Raw JSON payload. Overrides individual flags."`
	DryRun        bool   `optional:"" name:"dry-run" help:"Validate the request without executing it."`
}

func (c *VaultMappingsDeleteCmd) Run(out *output.Writer) error {
	input, err := vaultMappingInput(c.Json, c.Hostname, c.Path, c.Field, c.UsernameField)
	if err != nil {
		return err
	}
	if c.DryRun {
		return out.WriteDryRun("Would delete HashiCorp Vault mapping", input)
	}
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	mappings, err := client.DeleteVaultMapping(newContext(), project, input)
	if err != nil {
		return err
	}
	return out.Write(mappings)
}

// VaultPathsCmd is the `onecli hashicorp-vault paths` command group.
type VaultPathsCmd struct {
	List VaultPathsListCmd `cmd:"" help:"List children under a HashiCorp Vault KV path."`
}

type VaultPathsListCmd struct {
	Project string `optional:"" short:"p" help:"Project slug."`
	Path    string `optional:"" help:"Vault logical path to list."`
	Fields  string `optional:"" help:"Comma-separated list of fields to include in output."`
	Quiet   string `optional:"" name:"quiet" help:"Output only the specified field, one per line."`
}

func (c *VaultPathsListCmd) Run(out *output.Writer) error {
	if err := validate.NoControlChars(c.Path); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	entries, err := client.ListVaultPath(newContext(), project, c.Path)
	if err != nil {
		return err
	}
	if c.Quiet != "" {
		return out.WriteQuiet(entries, c.Quiet)
	}
	return out.WriteFiltered(entries, c.Fields)
}

// VaultSecretsCmd is the `onecli hashicorp-vault secrets` command group.
type VaultSecretsCmd struct {
	Metadata   VaultSecretsMetadataCmd   `cmd:"" help:"Show fields and mappings for a HashiCorp Vault secret path."`
	WriteField VaultSecretsWriteFieldCmd `cmd:"" name:"write-field" help:"Write one field to a HashiCorp Vault secret path."`
}

type VaultSecretsMetadataCmd struct {
	Project string `optional:"" short:"p" help:"Project slug."`
	Path    string `required:"" help:"Vault logical secret path."`
	Fields  string `optional:"" help:"Comma-separated list of fields to include in output."`
}

func (c *VaultSecretsMetadataCmd) Run(out *output.Writer) error {
	if err := validate.NoControlChars(c.Path); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	metadata, err := client.GetVaultSecretMetadata(newContext(), project, c.Path)
	if err != nil {
		return err
	}
	return out.WriteFiltered(metadata, c.Fields)
}

type VaultSecretsWriteFieldCmd struct {
	Project string `optional:"" short:"p" help:"Project slug."`
	Path    string `required:"" help:"Vault logical secret path."`
	Field   string `required:"" help:"Vault field to write."`
	Value   string `required:"" help:"Secret value to write."`
	DryRun  bool   `optional:"" name:"dry-run" help:"Validate the request without executing it."`
}

func (c *VaultSecretsWriteFieldCmd) Run(out *output.Writer) error {
	if err := validate.NoControlChars(c.Path); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	if c.Field == "" {
		return fmt.Errorf("field is required")
	}
	if err := validate.NoControlChars(c.Field); err != nil {
		return fmt.Errorf("invalid field: %w", err)
	}
	input := api.WriteVaultFieldsInput{
		Path:   c.Path,
		Fields: map[string]string{c.Field: c.Value},
	}
	if c.DryRun {
		return out.WriteDryRun("Would write HashiCorp Vault secret field", map[string]any{
			"path":   c.Path,
			"fields": []string{c.Field},
		})
	}
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	metadata, err := client.WriteVaultFields(newContext(), project, input)
	if err != nil {
		return err
	}
	return out.Write(metadata)
}

func vaultMappingInput(rawJSON, hostname, path, field, usernameField string) (api.UpsertVaultMappingInput, error) {
	var input api.UpsertVaultMappingInput
	if rawJSON != "" {
		if err := json.Unmarshal([]byte(rawJSON), &input); err != nil {
			return input, fmt.Errorf("invalid JSON payload: %w", err)
		}
	} else {
		input = api.UpsertVaultMappingInput{
			Hostname:      hostname,
			Path:          path,
			Field:         field,
			UsernameField: usernameField,
		}
	}
	if err := validate.NoControlChars(input.Hostname); err != nil {
		return input, fmt.Errorf("invalid hostname: %w", err)
	}
	if err := validate.NoControlChars(input.Path); err != nil {
		return input, fmt.Errorf("invalid path: %w", err)
	}
	if err := validate.NoControlChars(input.Field); err != nil {
		return input, fmt.Errorf("invalid field: %w", err)
	}
	if input.Hostname == "" || input.Path == "" || input.Field == "" {
		return input, fmt.Errorf("hostname, path, and field are required")
	}
	return input, nil
}
