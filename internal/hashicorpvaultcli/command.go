package hashicorpvaultcli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/onecli/onecli-cli/internal/api"
	"github.com/onecli/onecli-cli/pkg/output"
	"github.com/onecli/onecli-cli/pkg/validate"
)

// Client is the subset of the API client used by the HashiCorp Vault commands.
type Client interface {
	ListVaultMappings(ctx context.Context, projectID string) ([]api.VaultMapping, error)
	UpsertVaultMapping(ctx context.Context, projectID string, input api.UpsertVaultMappingInput) ([]api.VaultMapping, error)
	DeleteVaultMapping(ctx context.Context, projectID string, input api.UpsertVaultMappingInput) ([]api.VaultMapping, error)
	ListVaultPath(ctx context.Context, projectID, vaultPath string) ([]api.VaultPathEntry, error)
	GetVaultSecretMetadata(ctx context.Context, projectID, vaultPath string) (*api.VaultSecretMetadata, error)
	WriteVaultFields(ctx context.Context, projectID string, input api.WriteVaultFieldsInput) (*api.VaultSecretMetadata, error)
}

// Dependencies are provided by the main package so this command module stays
// isolated from root CLI setup and credential/config resolution.
type Dependencies struct {
	NewClient      func() (Client, error)
	NewContext     func() context.Context
	ResolveProject func(string) (string, error)
}

var deps Dependencies

// Configure wires the command module to the root CLI runtime.
func Configure(d Dependencies) {
	deps = d
}

// Command is the `onecli hashicorp-vault` command group.
type Command struct {
	Mappings MappingsCmd `cmd:"" help:"Manage HashiCorp Vault hostname mappings."`
	Paths    PathsCmd    `cmd:"" help:"Browse HashiCorp Vault KV paths."`
	Secrets  SecretsCmd  `cmd:"" help:"Inspect and write HashiCorp Vault secret fields."`
}

// MappingsCmd is the `onecli hashicorp-vault mappings` command group.
type MappingsCmd struct {
	List   MappingsListCmd   `cmd:"" help:"List HashiCorp Vault hostname mappings."`
	Set    MappingsSetCmd    `cmd:"" help:"Create or update a HashiCorp Vault hostname mapping."`
	Delete MappingsDeleteCmd `cmd:"" help:"Delete a HashiCorp Vault hostname mapping."`
}

type MappingsListCmd struct {
	Project string `optional:"" short:"p" help:"Project slug."`
	Fields  string `optional:"" help:"Comma-separated list of fields to include in output."`
	Quiet   string `optional:"" name:"quiet" help:"Output only the specified field, one per line."`
}

func (c *MappingsListCmd) Run(out *output.Writer) error {
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

type MappingsSetCmd struct {
	Project       string `optional:"" short:"p" help:"Project slug."`
	Hostname      string `required:"" help:"Upstream hostname, e.g. api.openai.com."`
	Path          string `required:"" help:"Vault logical secret path."`
	Field         string `required:"" help:"Vault field containing the credential value."`
	UsernameField string `optional:"" name:"username-field" help:"Optional Vault field containing a username."`
	Json          string `optional:"" help:"Raw JSON payload. Overrides individual flags."`
	DryRun        bool   `optional:"" name:"dry-run" help:"Validate the request without executing it."`
}

func (c *MappingsSetCmd) Run(out *output.Writer) error {
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

type MappingsDeleteCmd struct {
	Project       string `optional:"" short:"p" help:"Project slug."`
	Hostname      string `required:"" help:"Upstream hostname, e.g. api.openai.com."`
	Path          string `required:"" help:"Vault logical secret path."`
	Field         string `required:"" help:"Vault field containing the credential value."`
	UsernameField string `optional:"" name:"username-field" help:"Optional Vault field containing a username."`
	Json          string `optional:"" help:"Raw JSON payload. Overrides individual flags."`
	DryRun        bool   `optional:"" name:"dry-run" help:"Validate the request without executing it."`
}

func (c *MappingsDeleteCmd) Run(out *output.Writer) error {
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

// PathsCmd is the `onecli hashicorp-vault paths` command group.
type PathsCmd struct {
	List PathsListCmd `cmd:"" help:"List children under a HashiCorp Vault KV path."`
}

type PathsListCmd struct {
	Project string `optional:"" short:"p" help:"Project slug."`
	Path    string `optional:"" help:"Vault logical path to list."`
	Fields  string `optional:"" help:"Comma-separated list of fields to include in output."`
	Quiet   string `optional:"" name:"quiet" help:"Output only the specified field, one per line."`
}

func (c *PathsListCmd) Run(out *output.Writer) error {
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

// SecretsCmd is the `onecli hashicorp-vault secrets` command group.
type SecretsCmd struct {
	Metadata   SecretsMetadataCmd   `cmd:"" help:"Show fields and mappings for a HashiCorp Vault secret path."`
	WriteField SecretsWriteFieldCmd `cmd:"" name:"write-field" help:"Write one field to a HashiCorp Vault secret path."`
}

type SecretsMetadataCmd struct {
	Project string `optional:"" short:"p" help:"Project slug."`
	Path    string `required:"" help:"Vault logical secret path."`
	Fields  string `optional:"" help:"Comma-separated list of fields to include in output."`
}

func (c *SecretsMetadataCmd) Run(out *output.Writer) error {
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

type SecretsWriteFieldCmd struct {
	Project string `optional:"" short:"p" help:"Project slug."`
	Path    string `required:"" help:"Vault logical secret path."`
	Field   string `required:"" help:"Vault field to write."`
	Value   string `required:"" help:"Secret value to write."`
	DryRun  bool   `optional:"" name:"dry-run" help:"Validate the request without executing it."`
}

func (c *SecretsWriteFieldCmd) Run(out *output.Writer) error {
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

func newClient() (Client, error) {
	if deps.NewClient == nil {
		return nil, fmt.Errorf("hashicorp vault CLI dependencies are not configured")
	}
	return deps.NewClient()
}

func newContext() context.Context {
	if deps.NewContext == nil {
		return context.Background()
	}
	return deps.NewContext()
}

func resolveProject(project string) (string, error) {
	if deps.ResolveProject == nil {
		return project, nil
	}
	return deps.ResolveProject(project)
}
