package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListVaultMappings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/api/hashicorp-vault/mappings" {
			t.Errorf("path = %q, want /api/hashicorp-vault/mappings", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]VaultMapping{
			{Hostname: "api.openai.com", Path: "onecli/openai", Field: "api_key"},
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "oc_test")
	mappings, err := client.ListVaultMappings(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 || mappings[0].Hostname != "api.openai.com" {
		t.Errorf("got %+v", mappings)
	}
}

func TestUpsertVaultMapping(t *testing.T) {
	var gotBody UpsertVaultMappingInput
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %q, want PUT", r.Method)
		}
		if r.URL.Path != "/api/hashicorp-vault/mappings" {
			t.Errorf("path = %q, want /api/hashicorp-vault/mappings", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]VaultMapping{
			{Hostname: gotBody.Hostname, Path: gotBody.Path, Field: gotBody.Field},
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "oc_test")
	mappings, err := client.UpsertVaultMapping(
		context.Background(),
		"",
		UpsertVaultMappingInput{
			Hostname: "api.anthropic.com",
			Path:     "onecli/anthropic",
			Field:    "token",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotBody.Hostname != "api.anthropic.com" || len(mappings) != 1 {
		t.Errorf("got body %+v mappings %+v", gotBody, mappings)
	}
}

func TestListVaultPathEncodesQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/hashicorp-vault/paths" {
			t.Errorf("path = %q, want /api/hashicorp-vault/paths", r.URL.Path)
		}
		if got := r.URL.Query().Get("path"); got != "onecli/openai" {
			t.Errorf("path query = %q, want onecli/openai", got)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]VaultPathEntry{
			{Name: "openai", Path: "onecli/openai", Folder: false},
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "oc_test")
	entries, err := client.ListVaultPath(context.Background(), "", "onecli/openai")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "onecli/openai" {
		t.Errorf("got %+v", entries)
	}
}

func TestWriteVaultFields(t *testing.T) {
	var gotBody WriteVaultFieldsInput
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/api/hashicorp-vault/secrets/fields" {
			t.Errorf("path = %q, want /api/hashicorp-vault/secrets/fields", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(VaultSecretMetadata{
			Path:   gotBody.Path,
			Fields: []string{"api_key"},
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "oc_test")
	metadata, err := client.WriteVaultFields(
		context.Background(),
		"",
		WriteVaultFieldsInput{
			Path:   "onecli/openai",
			Fields: map[string]string{"api_key": "sk-test"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Path != "onecli/openai" || gotBody.Fields["api_key"] != "sk-test" {
		t.Errorf("got body %+v metadata %+v", gotBody, metadata)
	}
}
