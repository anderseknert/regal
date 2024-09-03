package io

import (
	"slices"
	"testing"

	"github.com/open-policy-agent/opa/util/test"
)

func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()

	type foo struct {
		Bar string `json:"bar"`
	}

	m := map[string]any{"bar": "foo"}
	f := foo{}

	if err := JSONRoundTrip(m, &f); err != nil {
		t.Fatal(err)
	}

	if f.Bar != "foo" {
		t.Errorf("expected JSON roundtrip to set struct value")
	}
}

func TestFindManifestLocations(t *testing.T) {
	t.Parallel()

	fs := map[string]string{
		"/.git":                          "",
		"/foo/bar/baz/.manifest":         "",
		"/foo/bar/qux/.manifest":         "",
		"/foo/bar/.regal/.manifest.yaml": "",
		"/node_modules/.manifest":        "",
	}

	test.WithTempFS(fs, func(root string) {
		locations, err := FindManifestLocations(root)
		if err != nil {
			t.Error(err)
		}

		if len(locations) != 2 {
			t.Errorf("expected 2 locations, got %d", len(locations))
		}

		expected := []string{"foo/bar/baz", "foo/bar/qux"}

		if !slices.Equal(locations, expected) {
			t.Errorf("expected %v, got %v", expected, locations)
		}
	})
}
