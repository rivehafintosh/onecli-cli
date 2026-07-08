package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/onecli/onecli-cli/pkg/output"
)

func TestProjectsCreateJSONDoesNotRequireNameFlag(t *testing.T) {
	var stdout bytes.Buffer
	cmd := ProjectsCreateCmd{
		Json:   `{"name":"From JSON"}`,
		DryRun: true,
	}
	if err := cmd.Run(output.NewWithWriters(&stdout, &bytes.Buffer{})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"name": "From JSON"`) {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestProjectsCreateRequiresName(t *testing.T) {
	cmd := ProjectsCreateCmd{DryRun: true}
	err := cmd.Run(output.NewWithWriters(&bytes.Buffer{}, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("expected missing-name error, got %v", err)
	}
}
