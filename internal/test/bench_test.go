package test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"

	jv1 "encoding/json"

	jsoniter "github.com/json-iterator/go"
	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/open-policy-agent/regal/bundle"
	_ "github.com/open-policy-agent/regal/internal/roast/encoding"
	"github.com/open-policy-agent/regal/internal/roast/encoding/exp"
)

func BenchmarkEncodeTerm(b *testing.B) {
	term := ast.StringTerm("foo")
	term.Location = ast.NewLocation([]byte("foo"), "p.rego", 4, 1)

	var bs2 []byte
	var err error

	bb := &bytes.Buffer{}
	enc := jsontext.NewEncoder(bb, exp.Opts)

	b.Run("jsoniter", func(b *testing.B) {
		for b.Loop() {
			if _, err = jsoniter.Marshal(term); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("json Marshal", func(b *testing.B) {
		for b.Loop() {
			if _, err = jv1.Marshal(term); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("json/v2 Marshal", func(b *testing.B) {
		for b.Loop() {
			if bs2, err = json.Marshal(term, exp.Opts); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("json/v2 MarshalEncode", func(b *testing.B) {
		for b.Loop() {
			bb.Reset()
			must0(b, json.MarshalEncode(enc, term, exp.Opts))
		}
	})

	if !bytes.Equal(bb.Bytes(), append(bs2, '\n')) {
		b.Fatalf("expected equal strings \n%s\n%s", bb.String(), string(bs2))
	}
}

func BenchmarkEncodeRefTermValueTypes(b *testing.B) {
	rt := ast.NewTerm(ast.MustParseRef("data.foo[1].bar[true].baz[[1, 2]]"))

	b.Run("json/v2 MarshalEncode", func(b *testing.B) {
		bb := new(bytes.Buffer)
		enc := jsontext.NewEncoder(bb, exp.Opts)

		for b.Loop() {
			bb.Reset()
			must0(b, json.MarshalEncode(enc, rt, exp.Opts))
		}
	})
}

func BenchmarkEncodeObject(b *testing.B) {
	o := ast.NewObject(
		ast.Item(ast.StringTerm("foo"), ast.StringTerm("bar")),
		ast.Item(ast.StringTerm("baz"), ast.IntNumberTerm(1)),
		ast.Item(ast.StringTerm("obj"), ast.ObjectTerm(
			ast.Item(ast.StringTerm("sub"), ast.BooleanTerm(true)),
		)),
	)

	bb := new(bytes.Buffer)

	b.Run("json/v2 MarshalEncode", func(b *testing.B) {
		enc := jsontext.NewEncoder(bb, exp.Opts)

		for b.Loop() {
			bb.Reset()
			must0(b, json.MarshalEncode(enc, o))
		}
	})
}

func BenchmarkMarshalRegalModules(b *testing.B) {
	ebFiles := bundle.EmbeddedBundle().Modules
	modules := make([]*ast.Module, 0, len(ebFiles))
	for _, mf := range ebFiles {
		modules = append(modules, mf.Parsed)
	}

	var err error

	b.Run("json/v2", func(b *testing.B) {
		bb := new(bytes.Buffer)
		enc := jsontext.NewEncoder(bb, exp.Opts)
		for b.Loop() {
			bb.Reset()
			must0(b, json.MarshalEncode(enc, modules))
		}
	})

	b.Run("jsoniter", func(b *testing.B) {
		for b.Loop() {
			if _, err = jsoniter.ConfigFastest.Marshal(modules); err != nil {
				b.Fatalf("failed to marshal module: %v", err)
			}
		}
	})

	b.Run("json/v1", func(b *testing.B) {
		for b.Loop() {
			if _, err := jv1.Marshal(modules); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// For pprof
func BenchmarkMarshalModuleOnlyV2(b *testing.B) {
	ebFiles := bundle.EmbeddedBundle().Modules
	modules := make([]*ast.Module, 0, len(ebFiles))
	for _, mf := range ebFiles {
		modules = append(modules, mf.Parsed)
	}

	bb := new(bytes.Buffer)
	enc := jsontext.NewEncoder(bb, exp.Opts)

	for b.Loop() {
		bb.Reset()
		must0(b, json.MarshalEncode(enc, modules))
	}
}

func must0(tb testing.TB, err error) {
	tb.Helper()

	if err != nil {
		tb.Fatal(err)
	}
}
