package encoding_test

import (
	"testing"

	jsoniter "github.com/json-iterator/go"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/open-policy-agent/regal/internal/test/assert"
)

func TestImportEncoding(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		policy   string
		expected string
	}{
		"regular import": {
			policy: "\n\nimport data.foo.bar",
			expected: `{"location":"3:1:3:7","path":{"location":"3:8:3:20","type":"ref","value":[` +
				`{"location":"3:8:3:12","type":"var","value":"data"},` +
				`{"location":"3:13:3:16","type":"string","value":"foo"},` +
				`{"location":"3:17:3:20","type":"string","value":"bar"}]}}`,
		},
		"aliased import": {
			policy: "\n\nimport data.foo.bar as baz",
			expected: `{"location":"3:1:3:7","path":{"location":"3:8:3:20","type":"ref","value":[` +
				`{"location":"3:8:3:12","type":"var","value":"data"},` +
				`{"location":"3:13:3:16","type":"string","value":"foo"},` +
				`{"location":"3:17:3:20","type":"string","value":"bar"}]},` +
				`"alias":"baz"}`,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			imp := ast.MustParseImports(tc.policy)[0]
			stream := jsoniter.ConfigFastest.BorrowStream(nil)

			t.Cleanup(func() {
				jsoniter.ConfigFastest.ReturnStream(stream)
			})

			stream.WriteVal(imp)
			assert.Equal(t, tc.expected, string(stream.Buffer()))
		})
	}
}
