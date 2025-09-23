package exp

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"reflect"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/regal/internal/util"
	"github.com/open-policy-agent/regal/pkg/roast/rast"
)

func MarshalToModule(enc *jsontext.Encoder, mod *ast.Module) (err error) {
	if err = beginObject(enc, nil); err == nil && mod.Package != nil {
		if err = enc.WriteToken(jsontext.String("package")); err == nil {
			if err = beginObject(enc, mod.Package.Location); err == nil && mod.Package.Path != nil {
				if err = enc.WriteToken(jsontext.String("path")); err != nil {
					return err
				}

				if err = enc.WriteToken(jsontext.BeginArray); err == nil {
					if err := json.MarshalEncode(enc, ast.DefaultRootDocument); err != nil {
						return err
					}

					for _, term := range mod.Package.Path[1:] {
						if err := json.MarshalEncode(enc, term); err != nil {
							return err
						}
					}
				}

				err = endArray(enc, err)
			}

			if err == nil && len(mod.Annotations) > 0 {
				var anyPkgAnno bool
				for _, a := range mod.Annotations {
					if a.Scope != "document" && a.Scope != "rule" {
						anyPkgAnno = true

						break
					}
				}
				if anyPkgAnno {
					if err = enc.WriteToken(jsontext.String("annotations")); err == nil {
						if err = enc.WriteToken(jsontext.BeginArray); err == nil {
							for _, a := range mod.Annotations {
								if a.Scope != "document" && a.Scope != "rule" {
									if err = json.MarshalEncode(enc, a); err != nil {
										return err
									}
								}
							}
						}

						err = endArray(enc, err)
					}
				}
			}

			err = endObject(enc, err)
		}
	}

	if err == nil && len(mod.Imports) > 0 {
		err = writeSliceAttr(enc, "imports", mod.Imports)
	}

	if err == nil && len(mod.Rules) > 0 {
		err = writeSliceAttr(enc, "rules", mod.Rules)
	}

	if err == nil && len(mod.Comments) > 0 {
		err = writeSliceAttr(enc, "comments", mod.Comments)
	}

	return endObject(enc, err)
}

func MarshalToPackage(enc *jsontext.Encoder, pkg *ast.Package) (err error) {
	err = beginObject(enc, pkg.Location)

	if err == nil && pkg.Path != nil {
		pathCopy := pkg.Path.Copy() // Copy to avoid data race: https://github.com/open-policy-agent/regal/issues/1167
		pathCopy[0].Location = nil  // Omit location of "data" part of path, at it isn't present in code

		err = writeSliceAttr(enc, "path", pathCopy)
	}

	return endObject(enc, err)
}

func MarshalToImport(enc *jsontext.Encoder, imp *ast.Import) (err error) {
	if err = beginObject(enc, imp.Location); err == nil && imp.Path != nil {
		if err = writeTermAttr(enc, "path", imp.Path); err == nil && imp.Alias != "" {
			if err = enc.WriteToken(jsontext.String("alias")); err == nil {
				err = MarshalToVar(enc, imp.Alias)
			}
		}
	}

	return endObject(enc, err)
}

func MarshalToComment(enc *jsontext.Encoder, c *ast.Comment) (err error) {
	if err = beginObject(enc, c.Location); err == nil {
		if err = enc.WriteToken(jsontext.String("text")); err == nil {
			buf := append(enc.AvailableBuffer(), '"')
			buf = base64.StdEncoding.AppendEncode(buf, c.Text)
			buf = append(buf, '"')

			err = enc.WriteValue(buf)
		}
	}

	return endObject(enc, err)
}

func MarshalToRule(enc *jsontext.Encoder, rule *ast.Rule) (err error) {
	err = beginObject(enc, rule.Location)
	if err == nil && len(rule.Annotations) > 0 {
		err = writeSliceAttr(enc, "annotations", rule.Annotations)
	}

	if err == nil && rule.Default {
		err = writeTokenPair(enc, "default", jsontext.True)
	}

	if err == nil && rule.Head != nil {
		if err = enc.WriteToken(jsontext.String("head")); err == nil {
			err = MarshalToHead(enc, rule.Head)
		}
	}

	if err == nil && !rast.IsBodyGenerated(rule) {
		err = writeSliceAttr(enc, "body", rule.Body)
	}

	if err == nil && rule.Else != nil {
		if err = enc.WriteToken(jsontext.String("else")); err == nil {
			err = MarshalToRule(enc, rule.Else)
		}
	}

	return endObject(enc, err)
}

func MarshalToAnnotations(enc *jsontext.Encoder, a *ast.Annotations) (err error) {
	if err = beginObject(enc, a.Location); err == nil {
		err = writeTokenPair(enc, "scope", jsontext.String(a.Scope))
	}

	if err == nil && a.Title != "" {
		err = writeTokenPair(enc, "title", jsontext.String(a.Title))
	}

	if err == nil && a.Description != "" {
		err = writeTokenPair(enc, "description", jsontext.String(a.Description))
	}

	if err == nil && a.Entrypoint {
		err = writeTokenPair(enc, "entrypoint", jsontext.True)
	}

	if err == nil && len(a.Organizations) > 0 {
		if err = enc.WriteToken(jsontext.String("organizations")); err == nil {
			err = writeStringSlice(enc, a.Organizations)
		}
	}

	if err == nil && len(a.RelatedResources) > 0 {
		err = writeSliceAttr(enc, "related_resources", a.RelatedResources)
	}

	if err == nil && len(a.Authors) > 0 {
		err = writeSliceAttr(enc, "authors", a.Authors)
	}

	if err == nil && len(a.Schemas) > 0 {
		err = writeSliceAttr(enc, "schemas", a.Schemas)
	}

	if err == nil && len(a.Custom) > 0 {
		if err = enc.WriteToken(jsontext.String("custom")); err == nil {
			err = json.MarshalEncode(enc, a.Custom) // Use default encoder of map[string]any
		}
	}

	return endObject(enc, err)
}

func MarshalToRelatedResourceAnnotation(enc *jsontext.Encoder, rr *ast.RelatedResourceAnnotation) (err error) {
	if err = beginObject(enc, nil); err == nil {
		if err = writeTokenPair(enc, "ref", jsontext.String(rr.Ref.String())); err == nil && len(rr.Description) > 0 {
			err = writeTokenPair(enc, "description", jsontext.String(rr.Description))
		}
	}

	return endObject(enc, err)
}

func MarshalToAuthorAnnotation(enc *jsontext.Encoder, aa *ast.AuthorAnnotation) (err error) {
	if err = beginObject(enc, nil); err == nil {
		if err = writeTokenPair(enc, "name", jsontext.String(aa.Name)); err == nil && len(aa.Email) > 0 {
			err = writeTokenPair(enc, "email", jsontext.String(aa.Email))
		}
	}

	return endObject(enc, err)
}

func MarshalToSchemaAnnotation(enc *jsontext.Encoder, sa *ast.SchemaAnnotation) (err error) {
	if err = beginObject(enc, nil); err == nil {
		if err = writeSliceAttr(enc, "path", sa.Path); err == nil {
			if sa.Schema != nil {
				err = writeSliceAttr(enc, "schema", sa.Schema)
			}
			if err == nil && sa.Definition != nil {
				err = json.MarshalEncode(enc, sa.Definition)
			}
		}
	}

	return endObject(enc, err)
}

func MarshalToHead(enc *jsontext.Encoder, head *ast.Head) (err error) {
	if err = beginObject(enc, head.Location); err == nil && head.Reference != nil {
		err = writeSliceAttr(enc, "ref", head.Reference)
	}

	if err == nil && len(head.Args) > 0 {
		err = writeSliceAttr(enc, "args", head.Args)
	}

	if err == nil && head.Assign {
		err = writeTokenPair(enc, "assign", jsontext.True)
	}

	if err == nil && head.Key != nil {
		err = writeTermAttr(enc, "key", head.Key)
	}

	if err == nil && head.Value != nil {
		// Strip location from generated `true` values, as they don't have one
		if head.Value.Location != nil && head.Location != nil {
			if head.Value.Location.Row == head.Location.Row && head.Value.Location.Col == head.Location.Col {
				head.Value.Location = nil
			}
		}

		err = writeTermAttr(enc, "value", head.Value)
	}

	return endObject(enc, err)
}

func MarshalToTerm(enc *jsontext.Encoder, term *ast.Term) error {
	if term.Value == nil {
		return nil
	}

	if err := beginObject(enc, term.Location); err != nil {
		return err
	}

	if err := writeTokenPair(enc, "type", jsontext.String(ast.ValueName(term.Value))); err != nil {
		return err
	}

	err := enc.WriteToken(jsontext.String("value"))
	if err == nil {
		err = MarshalToValue(enc, term.Value)
	}

	return endObject(enc, err)
}

func MarshalToValue(enc *jsontext.Encoder, value ast.Value) error {
	// Where possible, write tokens directly rather than calling json.MarshalEncode.
	// Even if these types have their own encoder functions, the pointer passed escapes to the heap.
	// Only for cases where the type itself is a pointer, we can safely dispatch to the MarshalEncode
	// function for that type.
	switch v := value.(type) {
	case ast.String:
		return MarshalToString(enc, v)
	case ast.Boolean:
		return MarshalToBoolean(enc, v)
	case ast.Null:
		return MarshalToNull(enc, v)
	case ast.Number:
		return MarshalToNumber(enc, v)
	case ast.Var:
		return MarshalToVar(enc, v)
	case ast.Ref:
		return MarshalToSlice(enc, v)
	case ast.Object:
		return MarshalToObject(enc, v)
	case ast.Set:
		return MarshalToSet(enc, v)
	case *ast.Array:
		return MarshalToArray(enc, v)
	case *ast.ArrayComprehension:
		return MarshalToArrayComprehension(enc, v)
	case *ast.SetComprehension:
		return MarshalToSetComprehension(enc, v)
	case *ast.ObjectComprehension:
		return MarshalToObjectComprehension(enc, v)
	case ast.Call:
		return MarshalToSlice(enc, v)
	}

	return fmt.Errorf("unknown value type %T for value %v", value, value)
}

func MarshalToVar(enc *jsontext.Encoder, s ast.Var) error {
	return enc.WriteToken(jsontext.String(string(s)))
}

func MarshalToString(enc *jsontext.Encoder, s ast.String) error {
	return enc.WriteToken(jsontext.String(string(s)))
}

func MarshalToBoolean(enc *jsontext.Encoder, b ast.Boolean) error {
	return enc.WriteToken(jsontext.Bool(bool(b)))
}

func MarshalToNull(enc *jsontext.Encoder, n ast.Null) error {
	return enc.WriteToken(jsontext.Null)
}

func MarshalToNumber(enc *jsontext.Encoder, n ast.Number) error {
	if i, ok := n.Int64(); ok {
		return enc.WriteToken(jsontext.Int(i))
	}
	if f, ok := n.Float64(); ok {
		return enc.WriteToken(jsontext.Float(f))
	}

	return fmt.Errorf("unknown number type %v", n)
}

func MarshalToArray(enc *jsontext.Encoder, a *ast.Array) (err error) {
	if err = enc.WriteToken(jsontext.BeginArray); err == nil {
		for i := range a.Len() {
			if err := json.MarshalEncode(enc, a.Elem(i)); err != nil {
				return err
			}
		}
	}

	return endArray(enc, err)
}

func MarshalToObject(enc *jsontext.Encoder, o ast.Object) (err error) {
	if err = enc.WriteToken(jsontext.BeginArray); err == nil {
		keys := o.Keys()
		rast.SortByLocation(keys)

		for _, key := range keys {
			if err := keyValEncoder(enc, key, o.Get(key)); err != nil {
				return err
			}
		}
	}

	return endArray(enc, err)
}

type set struct {
	elems map[int]*ast.Term
	keys  []*ast.Term
}

func MarshalToSet(enc *jsontext.Encoder, s ast.Set) error {
	keys := (*(*set)(reflect.ValueOf(s).UnsafePointer())).keys

	// Ensure we encode set values in the same order they appeared in the original source
	if !slices.IsSortedFunc(keys, rast.TermLocationSort) {
		keys = slices.Clone(keys)
		slices.SortStableFunc(keys, rast.TermLocationSort)
	}

	return MarshalToSlice(enc, keys)
}

func MarshalToLocation(enc *jsontext.Encoder, location *ast.Location) error {
	var newLine = []byte("\n")

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

	b := append(enc.AvailableBuffer(), '"')

	b = append(b, []byte(util.Itoa(location.Row))...)
	b = append(b, ':')
	b = append(b, []byte(util.Itoa(location.Col))...)
	b = append(b, ':')
	b = append(b, []byte(util.Itoa(endRow))...)
	b = append(b, ':')
	b = append(b, []byte(util.Itoa(endCol))...)

	return enc.WriteValue(append(b, '"'))
}

func MarshalToWith(enc *jsontext.Encoder, with *ast.With) (err error) {
	if err = beginObject(enc, with.Location); err == nil {
		if err = writeTermAttr(enc, "target", with.Target); err == nil {
			err = writeTermAttr(enc, "value", with.Value)
		}
	}

	return endObject(enc, err)
}

func MarshalToExpr(enc *jsontext.Encoder, expr *ast.Expr) (err error) {
	if err = beginObject(enc, expr.Location); err == nil && expr.Negated {
		err = writeTokenPair(enc, "negated", jsontext.True)
	}

	if err == nil && expr.Generated {
		err = writeTokenPair(enc, "generated", jsontext.True)
	}

	if err == nil && len(expr.With) > 0 {
		err = writeSliceAttr(enc, "with", expr.With)
	}

	if err == nil && expr.Terms != nil {
		if err = enc.WriteToken(jsontext.String("terms")); err == nil {
			switch t := expr.Terms.(type) {
			case *ast.Term:
				err = MarshalToTerm(enc, t)
			case []*ast.Term:
				err = MarshalToSlice(enc, t)
			case *ast.SomeDecl:
				err = MarshalToSomeDecl(enc, t)
			case *ast.Every:
				err = MarshalToEvery(enc, t)
			}
		}
	}

	return endObject(enc, err)
}

func MarshalToArrayComprehension(enc *jsontext.Encoder, ac *ast.ArrayComprehension) (err error) {
	if err = enc.WriteToken(jsontext.BeginObject); err == nil {
		if err = writeTermAttr(enc, "term", ac.Term); err == nil {
			err = writeSliceAttr(enc, "body", ac.Body)
		}
	}

	return endObject(enc, err)
}

func MarshalToSetComprehension(enc *jsontext.Encoder, sc *ast.SetComprehension) (err error) {
	if err = enc.WriteToken(jsontext.BeginObject); err == nil {
		if err = writeTermAttr(enc, "term", sc.Term); err == nil {
			err = writeSliceAttr(enc, "body", sc.Body)
		}
	}

	return endObject(enc, err)
}

func MarshalToObjectComprehension(enc *jsontext.Encoder, oc *ast.ObjectComprehension) (err error) {
	if err = enc.WriteToken(jsontext.BeginObject); err == nil {
		if err = writeTermAttr(enc, "key", oc.Key); err == nil {
			if err = writeTermAttr(enc, "value", oc.Value); err == nil {
				err = writeSliceAttr(enc, "body", oc.Body)
			}
		}
	}

	return endObject(enc, err)
}

func MarshalToSomeDecl(enc *jsontext.Encoder, sd *ast.SomeDecl) error {
	if err := beginObject(enc, sd.Location); err != nil {
		return err
	}

	return endObject(enc, writeSliceAttr(enc, "symbols", sd.Symbols))
}

func MarshalToEvery(enc *jsontext.Encoder, ev *ast.Every) (err error) {
	if err = beginObject(enc, ev.Location); err == nil {
		if err = writeTermAttr(enc, "key", ev.Key); err == nil {
			if err = writeTermAttr(enc, "value", ev.Value); err == nil {
				if err = writeTermAttr(enc, "domain", ev.Domain); err == nil {
					err = writeSliceAttr(enc, "body", ev.Body)
				}
			}
		}
	}

	return endObject(enc, err)
}

func keyValEncoder(enc *jsontext.Encoder, key *ast.Term, val *ast.Term) (err error) {
	if err = enc.WriteToken(jsontext.BeginArray); err == nil {
		if err = json.MarshalEncode(enc, key); err == nil {
			err = json.MarshalEncode(enc, val)
		}
	}

	return endArray(enc, err)
}

func beginObject(enc *jsontext.Encoder, location *ast.Location) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}

	return writeLocationAttrIfSet(enc, location)
}

func writeLocationAttrIfSet(enc *jsontext.Encoder, location *ast.Location) (err error) {
	if location != nil {
		if err = enc.WriteToken(jsontext.String("location")); err == nil {
			err = json.MarshalEncode(enc, location)
		}
	}

	return err
}

func writeTokenPair(enc *jsontext.Encoder, name string, t jsontext.Token) (err error) {
	if err = enc.WriteToken(jsontext.String(name)); err == nil {
		err = enc.WriteToken(t)
	}

	return err
}

func MarshalToSlice[T any](enc *jsontext.Encoder, s []*T) (err error) {
	if err = enc.WriteToken(jsontext.BeginArray); err == nil {
		for _, item := range s {
			if err := json.MarshalEncode(enc, item); err != nil {
				return err
			}
		}
	}

	return endArray(enc, err)
}

func writeStringSlice(enc *jsontext.Encoder, s []string) (err error) {
	if err = enc.WriteToken(jsontext.BeginArray); err == nil {
		for i := range s {
			if err := enc.WriteToken(jsontext.String(s[i])); err != nil {
				return err
			}
		}
	}

	return endArray(enc, err)
}

func writeSliceAttr[T any](enc *jsontext.Encoder, name string, s []*T) (err error) {
	if err = enc.WriteToken(jsontext.String(name)); err == nil {
		err = MarshalToSlice(enc, s)
	}

	return err
}

func writeTermAttr(enc *jsontext.Encoder, name string, term *ast.Term) (err error) {
	if err = enc.WriteToken(jsontext.String(name)); err == nil {
		err = json.MarshalEncode(enc, term)
	}

	return err
}

func endObject(enc *jsontext.Encoder, err error) error {
	if err != nil {
		return err
	}

	return enc.WriteToken(jsontext.EndObject)
}

func endArray(enc *jsontext.Encoder, err error) error {
	if err != nil {
		return err
	}

	return enc.WriteToken(jsontext.EndArray)
}
