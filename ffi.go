package cedar

import (
	"context"
	"encoding/json"
	"fmt"
)

// FFIResponse is the response from the Foreign Function Interface (FFI) of the cedar_policy library.
type FFIResponse struct {
	// IsSuccess is true if the request was successful.
	// If false, the Errors field will contain the errors that occurred.
	IsSuccess bool   `json:"success,string,omitempty"`
	RawResult string `json:"result,omitempty"`
	// Result is the result of the policy evaluation.
	Result EvalResponse `json:"-"`
	// IsInternal is true if the request failed due to an internal error.
	IsInternal bool `json:"isInternal,omitempty"`
	// Errors is the list of errors that occurred during evaluation.
	Errors []string `json:"errors,omitempty"`
}

// FFI gives access to the Foreign Function Interface (FFI) of the cedar_policy library.
// See https://docs.rs/cedar-policy/latest/cedar_policy/frontend/is_authorized/fn.json_is_authorized.html for more information.
func (c *CedarEngine) FFI(ctx context.Context, input string) (FFIResponse, error) {
	inputSize := uint64(len(input))
	inputPtr, err := c.exportedFuncs[string(allocate)].Call(ctx, inputSize)
	if err != nil {
		return FFIResponse{}, err
	}
	defer c.exportedFuncs[string(deallocate)].Call(ctx, inputPtr[0], inputSize)
	ok := c.module.Memory().WriteString(uint32(inputPtr[0]), input)
	if !ok {
		return FFIResponse{}, fmt.Errorf("failed to write input to memory")
	}
	resPtr, err := c.exportedFuncs[string(ffi)].Call(ctx, inputPtr[0], inputSize)
	if err != nil {
		return FFIResponse{}, err
	}
	var res FFIResponse
	output, err := c.readDecisionFromMemory(ctx, resPtr[0])
	if err != nil {
		return FFIResponse{}, err
	}
	err = json.Unmarshal(output, &res)
	if err != nil {
		return FFIResponse{}, err
	}
	if !res.IsSuccess {
		return res, nil
	}
	var result EvalResponse
	err = json.Unmarshal([]byte(res.RawResult), &result)
	if err != nil {
		return FFIResponse{}, err
	}
	res.Result = result
	return res, nil
}
