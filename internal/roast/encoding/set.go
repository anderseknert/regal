package encoding

import (
	"slices"
	"sync"
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/open-policy-agent/regal/internal/roast/encoding/util"
	"github.com/open-policy-agent/regal/pkg/roast/rast"
)

type setCodec struct{}

func (*setCodec) IsEmpty(_ unsafe.Pointer) bool {
	return false
}

type set struct {
	elems     map[int]*ast.Term
	keys      []*ast.Term
	hash      int
	ground    bool
	sortGuard *sync.Once
}

func (*setCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	s := *((*set)(ptr))

	keys := s.keys
	if !slices.IsSortedFunc(keys, rast.TermLocationSort) {
		keys = slices.Clone(keys)
		slices.SortStableFunc(keys, rast.TermLocationSort)
	}

	util.WriteValsArray(stream, keys)
}
