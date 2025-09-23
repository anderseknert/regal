package exp

import (
	"encoding/json/v2"

	"github.com/open-policy-agent/opa/v1/ast"
)

var Opts = json.JoinOptions(
	json.DefaultOptionsV2(),
	// Note: For best performance, more specific types should be listed
	// before more generic ones, i.e. handler for ast.String before ast.Value.
	// Also note that for the same reason, marshal functions should take
	// pointer values.
	json.WithMarshalers(json.JoinMarshalers(
		json.MarshalToFunc(MarshalToTerm),

		// ast.Value implementations
		json.MarshalToFunc(MarshalToSlice[ast.Ref]),
		json.MarshalToFunc(MarshalToSlice[ast.Call]),
		json.MarshalToFunc(MarshalToLocation),
		json.MarshalToFunc(MarshalToString),
		json.MarshalToFunc(MarshalToBoolean),
		json.MarshalToFunc(MarshalToNull),
		json.MarshalToFunc(MarshalToNumber),
		json.MarshalToFunc(MarshalToVar),
		json.MarshalToFunc(MarshalToArray),
		json.MarshalToFunc(MarshalToObject),
		json.MarshalToFunc(MarshalToSet),
		json.MarshalToFunc(MarshalToArrayComprehension),
		json.MarshalToFunc(MarshalToSetComprehension),
		json.MarshalToFunc(MarshalToObjectComprehension),
		// should never have to be called, as every value covered
		// above, but included for good measure
		json.MarshalToFunc(MarshalToValue),

		json.MarshalToFunc(MarshalToSomeDecl),
		json.MarshalToFunc(MarshalToEvery),
		json.MarshalToFunc(MarshalToWith),
		json.MarshalToFunc(MarshalToExpr),
		json.MarshalToFunc(MarshalToSlice[ast.Body]),

		json.MarshalToFunc(MarshalToModule),
		json.MarshalToFunc(MarshalToPackage),
		json.MarshalToFunc(MarshalToImport),
		json.MarshalToFunc(MarshalToRule),
		json.MarshalToFunc(MarshalToHead),
		json.MarshalToFunc(MarshalToComment),

		json.MarshalToFunc(MarshalToAnnotations),
		json.MarshalToFunc(MarshalToRelatedResourceAnnotation),
		json.MarshalToFunc(MarshalToAuthorAnnotation),
		json.MarshalToFunc(MarshalToSchemaAnnotation),
	)),
)
