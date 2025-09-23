package encoding

import (
	"slices"
	"sync"
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/open-policy-agent/opa/v1/ast"
)

type objectCodec struct{}

func (*objectCodec) IsEmpty(_ unsafe.Pointer) bool {
	return false
}

type object struct {
	elems     map[int]*objectElem
	keys      objectElemSlice
	ground    int
	hash      int
	sortGuard *sync.Once
}

type objectElem struct {
	key   *ast.Term
	value *ast.Term
	next  *objectElem //nolint:unused
}

type objectElemSlice []*objectElem

func (*objectCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	o := *((*object)(ptr))

	stream.WriteArrayStart()

	keys := o.keys
	if !slices.IsSortedFunc(keys, objectElemSliceLocSort) {
		keys = slices.Clone(keys)
		slices.SortStableFunc(keys, objectElemSliceLocSort)
	}

	for i, node := range keys {
		if i > 0 {
			stream.WriteMore()
		}

		stream.WriteArrayStart()
		stream.WriteVal(node.key)
		stream.WriteMore()
		stream.WriteVal(node.value)
		stream.WriteArrayEnd()
	}

	stream.WriteArrayEnd()
}

func objectElemSliceLocSort(a, b *objectElem) int {
	if a.key.Location == nil {
		return 1
	}

	return a.key.Location.Compare(b.key.Location)
}
