package dap

import (
	"errors"

	godap "github.com/google/go-dap"
	"github.com/open-policy-agent/opa/v1/debug"
)

func evalInFrame(s debug.Session, frameID debug.FrameID, expr string) (*godap.EvaluateResponse, error) {
	vars, err := getLocalsForFrame(s, frameID)
	if err != nil {
		return nil, err
	}

	for _, v := range vars {
		if v.Name() == expr {
			return NewEvaluateResponse(godap.EvaluateResponseBody{
				Type:               v.Type(),
				Result:             v.Value(),
				VariablesReference: int(v.VariablesReference()),
			}), nil
		}
	}

	return NewEvaluateResponse(godap.EvaluateResponseBody{}), errors.New("undefined (only variable lookup supported)")
}

func getLocalsForFrame(s debug.Session, frameID debug.FrameID) (locals []debug.Variable, err error) {
	scopes, err := s.Scopes(frameID)
	if err != nil {
		return nil, err
	}

	for _, scope := range scopes {
		if scope.Name() == "Locals" {
			if vars, err := s.Variables(scope.VariablesReference()); err == nil {
				locals = append(locals, vars...)
			}
		}
	}

	return locals, nil
}
