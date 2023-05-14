package cedar

import (
	"context"
	_ "embed"
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
	evalSize := uint64(len(req.Principal) + len(req.Action) + len(req.Resource) + len(req.Context))
	evalPtr, err := c.exportedFuncs[string(allocate)].Call(ctx, evalSize)
	if err != nil {
		return "", err
	}
	defer c.exportedFuncs[string(deallocate)].Call(ctx, evalPtr[0], evalSize)
	ok := c.module.Memory().WriteString(uint32(evalPtr[0]), req.Principal)
	if !ok {
		return "", fmt.Errorf("failed to write principal to memory")
	}
	offset := uint32(0)
	offset += uint32(len(req.Principal))
	ok = c.module.Memory().WriteString(uint32(evalPtr[0])+offset, req.Action)
	if !ok {
		return "", fmt.Errorf("failed to write action to memory")
	}
	offset += uint32(len(req.Action))
	ok = c.module.Memory().WriteString(uint32(evalPtr[0])+offset, req.Resource)
	if !ok {
		return "", fmt.Errorf("failed to write resource to memory")
	}
	offset += uint32(len(req.Resource))
	ok = c.module.Memory().WriteString(uint32(evalPtr[0])+offset, req.Context)
	if !ok {
		return "", fmt.Errorf("failed to write context to memory")
	}
	resPtr, err := c.exportedFuncs[string(isAuthorized)].Call(
		ctx,
		evalPtr[0],
		uint64(len(req.Principal)),
		evalPtr[0]+uint64(len(req.Principal)),
		uint64(len(req.Action)),
		evalPtr[0]+uint64(len(req.Principal))+uint64(len(req.Action)),
		uint64(len(req.Resource)),
		evalPtr[0]+uint64(len(req.Principal))+uint64(len(req.Action))+uint64(len(req.Resource)),
		uint64(len(req.Context)),
	)
	if err != nil {
		return "", err
	}
	decisionPtr := uint32(resPtr[0] >> 32)
	decisionSize := uint32(resPtr[0])
	defer c.exportedFuncs[string(deallocate)].Call(ctx, uint64(decisionPtr), uint64(decisionSize))
	decision, ok := c.module.Memory().Read(decisionPtr, decisionSize)
	if !ok {
		return "", fmt.Errorf("failed to read decision from memory")
	}
	return EvalResult(decision), nil
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
