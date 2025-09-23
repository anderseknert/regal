package exp

import (
	"encoding/json/v2"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

func TestMarshalTerm(t *testing.T) {
	term := ast.StringTerm("foo")

	bs, err := json.Marshal(term, Opts)
	if err != nil {
		t.Fatal(err)
	}

	if exp := `{"type":"string","value":"foo"}`; string(bs) != exp {
		t.Fatalf("expected %s, got %s", exp, string(bs))
	}
}

func TestMarshalTermWithLocation(t *testing.T) {
	term := ast.StringTerm("foo")
	term.Location = ast.NewLocation([]byte("foo"), "p.rego", 4, 1)

	bs, err := json.Marshal(term, Opts)
	if err != nil {
		t.Fatal(err)
	}

	if exp := `{"location":"4:1:4:4","type":"string","value":"foo"}`; string(bs) != exp {
		t.Fatalf("expected %s, got %s", exp, string(bs))
	}
}
