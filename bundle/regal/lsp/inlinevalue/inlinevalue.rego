# METADATA
# schemas:
#   - input:        schema.regal.lsp.common
#   - input.params: schema.regal.lsp.inlinevalue
package regal.lsp.inlinevalue

# import data.regal.ast
import data.regal.lsp.util.range
import data.regal.util

# METADATA
# entrypoint: true
default result["response"] := null

result["response"] := values if {
	module := data.workspace.parsed[input.params.textDocument.uri]

	row := input.params.context.stoppedLocation.start.line + 1
	[_, rule] := _rule_at_line(module.rules, row)

	exprs := [value |
		some expr in _exprs(rule.body, row)

		expr.terms[0].value[0].type == "var"
		expr.terms[0].value[0].value == "equal"

		loc := util.to_location_object(expr.location)

		print(loc.text)

		value := {
			"expression": loc.text,
			"range": range.parse(expr.location),
		}
	]

	vars := array.flatten([
		[var | some var in _assignment_vars(_exprs(rule.body, row))],
		[],
	])

	values := array.flatten([exprs, vars])

	print("inlinevalue values: ", values)
}

_assignment_vars(exprs) := [var |
	some expr in exprs
	expr.terms[0].value[0].type == "var"
	expr.terms[0].value[0].value == "assign"

	term := expr.terms[1]

	var := {
		"variableName": term.value,
		"caseSensitiveLookup": true,
		"range": range.parse(term.location),
	}
]

# all expressions before and on the given row
_exprs(exprs, row) := [expr |
	some expr in exprs

	loc := util.to_location_object(expr.location)
	row >= loc.row

	print("expr at row:", row)
]

_rule_at_line(rules, row) := [rule_index, rule] if {
	some rule_index, rule in rules

	loc := util.to_location_object(rule.location)

	row >= loc.row
	row <= loc.end.row
}
