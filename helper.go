package cedar

import (
	"context"
	"fmt"
)

// writeEvalRequestInMemory writes the eval request to the wasm memory.
func (c *CedarEngine) writeEvalRequestInMemory(ctx context.Context, req EvalRequest) (uint64, error) {
	evalSize := uint64(len(req.Principal) + len(req.Action) + len(req.Resource) + len(req.Context))
	evalPtr, err := c.exportedFuncs[string(allocate)].Call(ctx, evalSize)
	if err != nil {
		return 0, err
	}
	ok := c.module.Memory().WriteString(uint32(evalPtr[0]), req.Principal)
	if !ok {
		return 0, fmt.Errorf("failed to write principal to memory")
	}
	offset := uint32(0)
	offset += uint32(len(req.Principal))
	ok = c.module.Memory().WriteString(uint32(evalPtr[0])+offset, req.Action)
	if !ok {
		return 0, fmt.Errorf("failed to write action to memory")
	}
	offset += uint32(len(req.Action))
	ok = c.module.Memory().WriteString(uint32(evalPtr[0])+offset, req.Resource)
	if !ok {
		return 0, fmt.Errorf("failed to write resource to memory")
	}
	offset += uint32(len(req.Resource))
	ok = c.module.Memory().WriteString(uint32(evalPtr[0])+offset, req.Context)
	if !ok {
		return 0, fmt.Errorf("failed to write context to memory")
	}
	return evalPtr[0], nil
}

// deallocateEvalRequestInMemory deallocates the eval request from the wasm memory.
func (c *CedarEngine) deallocateEvalRequestInMemory(ctx context.Context, ptr uint64, req EvalRequest) error {
	length := uint64(len(req.Principal) + len(req.Action) + len(req.Resource) + len(req.Context))
	_, err := c.exportedFuncs[string(deallocate)].Call(ctx, ptr, length)
	return err
}

// readDecisionFromMemory reads the decision from the wasm memory.
func (c *CedarEngine) readDecisionFromMemory(ctx context.Context, ptr uint64) ([]byte, error) {
	decisionPtr := uint32(ptr >> 32)
	decisionSize := uint32(ptr)
	defer c.exportedFuncs[string(deallocate)].Call(ctx, uint64(decisionPtr), uint64(decisionSize))
	decision, ok := c.module.Memory().Read(decisionPtr, decisionSize)
	if !ok {
		return []byte{}, fmt.Errorf("failed to read decision from memory")
	}
	return decision, nil
}
