package cedar

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed static/cedar.wasm
var cedarWasm []byte

// CedarEngine is an instance of the cedar wasm engine.
type CedarEngine struct {
	runtime       wazero.Runtime
	module        api.Module
	exportedFuncs map[string]api.Function
}

// NewCedarEngine creates a new instance of the cedar wasm engine.
// This is blocking and may take a while to complete. Ensure you do not call this from a hot path.
func NewCedarEngine(ctx context.Context) (*CedarEngine, error) {
	r := wazero.NewRuntime(ctx)
	module, err := r.Instantiate(ctx, cedarWasm)
	if err != nil {
		return nil, err
	}
	return &CedarEngine{
		runtime:       r,
		module:        module,
		exportedFuncs: exportFuncs(module),
	}, nil
}

// SetEntitiesFromJson sets the entities in the engine from a json string.
// See https://docs.cedarpolicy.com/syntax-entity.html for more information.
func (c *CedarEngine) SetEntitiesFromJson(ctx context.Context, entities string) error {
	entitiesSize := uint64(len(entities))
	entitiesPtr, err := c.exportedFuncs[string(allocate)].Call(ctx, entitiesSize)
	if err != nil {
		return err
	}
	defer c.exportedFuncs[string(deallocate)].Call(ctx, entitiesPtr[0], entitiesSize)
	ok := c.module.Memory().WriteString(uint32(entitiesPtr[0]), entities)
	if !ok {
		return fmt.Errorf("failed to write entities to memory")
	}
	_, err = c.exportedFuncs[string(setEntities)].Call(ctx, entitiesPtr[0], entitiesSize)
	return err
}

// SetPolicies sets the policies in the engine from a string.
// See https://docs.cedarpolicy.com/syntax-policy.htmle for more information.
func (c *CedarEngine) SetPolicies(ctx context.Context, policies string) error {
	policiesSize := uint64(len(policies))
	policiesPtr, err := c.exportedFuncs[string(allocate)].Call(ctx, policiesSize)
	if err != nil {
		return err
	}
	defer c.exportedFuncs[string(deallocate)].Call(ctx, policiesPtr[0], policiesSize)
	ok := c.module.Memory().WriteString(uint32(policiesPtr[0]), policies)
	if !ok {
		return fmt.Errorf("failed to write policies to memory")
	}
	_, err = c.exportedFuncs[string(setPolicies)].Call(ctx, policiesPtr[0], policiesSize)
	return err
}

// Eval evaluates the request against the policies and entities in the engine.
// See EvalRequest for more information.
func (c *CedarEngine) Eval(ctx context.Context, req EvalRequest) (EvalResult, error) {
	evalPtr, err := c.writeEvalRequestInMemory(ctx, req)
	if err != nil {
		return "", err
	}
	defer c.deallocateEvalRequestInMemory(ctx, evalPtr, req)
	resPtr, err := c.exportedFuncs[string(isAuthorizedString)].Call(
		ctx,
		evalPtr,
		uint64(len(req.Principal)),
		evalPtr+uint64(len(req.Principal)),
		uint64(len(req.Action)),
		evalPtr+uint64(len(req.Principal))+uint64(len(req.Action)),
		uint64(len(req.Resource)),
		evalPtr+uint64(len(req.Principal))+uint64(len(req.Action))+uint64(len(req.Resource)),
		uint64(len(req.Context)),
	)
	if err != nil {
		return "", err
	}
	decision, err := c.readDecisionFromMemory(ctx, resPtr[0])
	return EvalResult(decision), nil
}

// EvalWithResponse evaluates the request against the policies and entities in the engine.
// Returns the result as a json string.
func (c *CedarEngine) EvalWithResponse(ctx context.Context, req EvalRequest) (EvalResponse, error) {
	evalPtr, err := c.writeEvalRequestInMemory(ctx, req)
	if err != nil {
		return EvalResponse{}, err
	}
	defer c.deallocateEvalRequestInMemory(ctx, evalPtr, req)
	resPtr, err := c.exportedFuncs[string(isAuthorizedJSON)].Call(
		ctx,
		evalPtr,
		uint64(len(req.Principal)),
		evalPtr+uint64(len(req.Principal)),
		uint64(len(req.Action)),
		evalPtr+uint64(len(req.Principal))+uint64(len(req.Action)),
		uint64(len(req.Resource)),
		evalPtr+uint64(len(req.Principal))+uint64(len(req.Action))+uint64(len(req.Resource)),
		uint64(len(req.Context)),
	)
	if err != nil {
		return EvalResponse{}, err
	}
	decision, err := c.readDecisionFromMemory(ctx, resPtr[0])
	var evalResponse EvalResponse
	err = json.Unmarshal(decision, &evalResponse)
	if err != nil {
		return EvalResponse{}, err
	}
	return evalResponse, nil
}

// IsAuthorizedPartial partially evaluates authorization request.
// If the Authorizer can reach a response, it will return that response.
// Otherwise, it will return a list of residual policies that still need to be evaluated.
// See https://docs.rs/cedar-policy/latest/cedar_policy/struct.Authorizer.html#method.is_authorized_partial
func (c *CedarEngine) IsAuthorizedPartial(ctx context.Context, req EvalRequest) (string, error) {
	evalPtr, err := c.writeEvalRequestInMemory(ctx, req)
	if err != nil {
		return "", err
	}
	defer c.deallocateEvalRequestInMemory(ctx, evalPtr, req)
	resPtr, err := c.exportedFuncs[string(isAuthorizedPartial)].Call(
		ctx,
		evalPtr,
		uint64(len(req.Principal)),
		evalPtr+uint64(len(req.Principal)),
		uint64(len(req.Action)),
		evalPtr+uint64(len(req.Principal))+uint64(len(req.Action)),
		uint64(len(req.Resource)),
		evalPtr+uint64(len(req.Principal))+uint64(len(req.Action))+uint64(len(req.Resource)),
		uint64(len(req.Context)),
	)
	if err != nil {
		return "", err
	}
	decision, err := c.readDecisionFromMemory(ctx, resPtr[0])
	return string(decision), nil
}

// IsAuthorized evaluates the request against the policies and entities in the engine and returns true if the request is authorized.
// It is a convenience method that is equivalent to calling Eval and checking the result.
// See Eval for more information.
func (c *CedarEngine) IsAuthorized(ctx context.Context, req EvalRequest) (bool, error) {
	res, err := c.Eval(ctx, req)
	if err != nil {
		return false, err
	}
	return res.IsPermit(), nil
}

// Close closes the engine and cleanup the wasm runtime.
// Ensure you call this when you are done with the engine to free up resources used by the engine.
func (c *CedarEngine) Close(ctx context.Context) error {
	return c.runtime.Close(ctx)
}
