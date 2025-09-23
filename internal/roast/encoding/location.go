package encoding

import (
	"bytes"
	"strings"
	"sync"
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/regal/internal/util"
)

type locationCodec struct{}

var newLine = []byte("\n")

var sbPool = sync.Pool{
	New: func() any {
		return new(strings.Builder)
	},
}

func (*locationCodec) IsEmpty(_ unsafe.Pointer) bool {
	return false
}

func (*locationCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	location := *((*ast.Location)(ptr))

	endRow := location.Row
	endCol := location.Col

	if location.Text != nil {
		if !bytes.Contains(location.Text, newLine) {
			// single line
			endCol = location.Col + len(location.Text)
		} else {
			// multi line
			numLines := bytes.Count(location.Text, newLine) + 1
			endRow = location.Row + numLines - 1

			if numLines == 1 {
				endCol = location.Col + len(location.Text)
			} else {
				lastLine := location.Text[bytes.LastIndexByte(location.Text, '\n')+1:]
				endCol = len(lastLine) + 1
			}
		}
	}

	sb := sbPool.Get().(*strings.Builder) //nolint:forcetypeassert

	sb.WriteString(util.Itoa(location.Row))
	sb.WriteByte(':')
	sb.WriteString(util.Itoa(location.Col))
	sb.WriteByte(':')
	sb.WriteString(util.Itoa(endRow))
	sb.WriteByte(':')
	sb.WriteString(util.Itoa(endCol))

	stream.WriteString(sb.String())

	sb.Reset()
	sbPool.Put(sb)
}
