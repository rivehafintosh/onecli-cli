package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// VaultMapping maps a Vault secret field to an upstream hostname.
type VaultMapping struct {
	Hostname      string `json:"hostname"`
	Path          string `json:"path"`
	Field         string `json:"field"`
	UsernameField string `json:"username_field,omitempty"`
}

// UpsertVaultMappingInput is the request body for adding or deleting a mapping.
type UpsertVaultMappingInput struct {
	Hostname      string `json:"hostname"`
	Path          string `json:"path"`
	Field         string `json:"field"`
	UsernameField string `json:"usernameField,omitempty"`
}

// VaultPathEntry is a browsable Vault KV path entry.
type VaultPathEntry struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Folder bool   `json:"folder"`
}

// VaultSecretMetadata describes fields and hostname mappings for a Vault path.
type VaultSecretMetadata struct {
	Path     string         `json:"path"`
	Fields   []string       `json:"fields"`
	Mappings []VaultMapping `json:"mappings"`
}

// WriteVaultFieldsInput is the request body for writing Vault secret fields.
type WriteVaultFieldsInput struct {
	Path   string            `json:"path"`
	Fields map[string]string `json:"fields"`
}

// ListVaultMappings returns configured HashiCorp Vault hostname mappings.
func (c *Client) ListVaultMappings(ctx context.Context, projectID string) ([]VaultMapping, error) {
	path := withProjectQuery("/api/hashicorp-vault/mappings", projectID)
	var mappings []VaultMapping
	if err := c.do(ctx, http.MethodGet, path, nil, &mappings); err != nil {
		return nil, fmt.Errorf("listing HashiCorp Vault mappings: %w", err)
	}
	return mappings, nil
}

// UpsertVaultMapping creates or updates a HashiCorp Vault hostname mapping.
func (c *Client) UpsertVaultMapping(ctx context.Context, projectID string, input UpsertVaultMappingInput) ([]VaultMapping, error) {
	path := withProjectQuery("/api/hashicorp-vault/mappings", projectID)
	var mappings []VaultMapping
	if err := c.do(ctx, http.MethodPut, path, input, &mappings); err != nil {
		return nil, fmt.Errorf("saving HashiCorp Vault mapping: %w", err)
	}
	return mappings, nil
}

// DeleteVaultMapping removes a HashiCorp Vault hostname mapping.
func (c *Client) DeleteVaultMapping(ctx context.Context, projectID string, input UpsertVaultMappingInput) ([]VaultMapping, error) {
	path := withProjectQuery("/api/hashicorp-vault/mappings", projectID)
	var mappings []VaultMapping
	if err := c.do(ctx, http.MethodDelete, path, input, &mappings); err != nil {
		return nil, fmt.Errorf("deleting HashiCorp Vault mapping: %w", err)
	}
	return mappings, nil
}

// ListVaultPath lists children under a HashiCorp Vault KV path.
func (c *Client) ListVaultPath(ctx context.Context, projectID, vaultPath string) ([]VaultPathEntry, error) {
	q := url.Values{}
	q.Set("path", vaultPath)
	if projectID != "" {
		q.Set("projectId", projectID)
	}
	var entries []VaultPathEntry
	if err := c.do(ctx, http.MethodGet, "/api/hashicorp-vault/paths?"+q.Encode(), nil, &entries); err != nil {
		return nil, fmt.Errorf("listing HashiCorp Vault path: %w", err)
	}
	return entries, nil
}

// GetVaultSecretMetadata returns fields and mappings for a Vault KV path.
func (c *Client) GetVaultSecretMetadata(ctx context.Context, projectID, vaultPath string) (*VaultSecretMetadata, error) {
	q := url.Values{}
	q.Set("path", vaultPath)
	if projectID != "" {
		q.Set("projectId", projectID)
	}
	var metadata VaultSecretMetadata
	if err := c.do(ctx, http.MethodGet, "/api/hashicorp-vault/secrets/metadata?"+q.Encode(), nil, &metadata); err != nil {
		return nil, fmt.Errorf("getting HashiCorp Vault secret metadata: %w", err)
	}
	return &metadata, nil
}

// WriteVaultFields writes one or more fields to a Vault KV path.
func (c *Client) WriteVaultFields(ctx context.Context, projectID string, input WriteVaultFieldsInput) (*VaultSecretMetadata, error) {
	path := withProjectQuery("/api/hashicorp-vault/secrets/fields", projectID)
	var metadata VaultSecretMetadata
	if err := c.do(ctx, http.MethodPost, path, input, &metadata); err != nil {
		return nil, fmt.Errorf("writing HashiCorp Vault secret fields: %w", err)
	}
	return &metadata, nil
}
