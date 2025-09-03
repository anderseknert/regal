package encoding

import (
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/open-policy-agent/regal/internal/roast/encoding/util"
)

type exprCodec struct{}

func (*exprCodec) IsEmpty(_ unsafe.Pointer) bool {
	return false
}

func (*exprCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	expr := *((*ast.Expr)(ptr))

	util.ObjectStart(stream, expr.Location)

	if expr.Negated {
		util.WriteBool(stream, strNegated, expr.Negated)
	}

	if expr.Generated {
		util.WriteBool(stream, strGenerated, expr.Generated)
	}

	if len(expr.With) > 0 {
		util.WriteValsArrayAttr(stream, strWith, expr.With)
	}

	if expr.Terms != nil {
		stream.WriteObjectField(strTerms)

		switch t := expr.Terms.(type) {
		case *ast.Term:
			stream.WriteVal(t)
		case []*ast.Term:
			util.WriteValsArray(stream, t)
		case *ast.SomeDecl:
			stream.WriteVal(t)
		case *ast.Every:
			stream.WriteVal(t)
		}
	}

	util.ObjectEnd(stream)
}
