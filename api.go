package cedar

import "github.com/tetratelabs/wazero/api"

type function string

const (
	allocate     function = "allocate"
	deallocate   function = "deallocate"
	setEntities  function = "set_entities"
	setPolicies  function = "set_policies"
	isAuthorized function = "is_authorized"
)

// exportFuncs returns a map of exported functions from the wasm module.
func exportFuncs(module api.Module) map[string]api.Function {
	exportedFuncs := make(map[string]api.Function)
	exportedFuncs[string(isAuthorized)] = module.ExportedFunction(string(isAuthorized))
	exportedFuncs[string(setEntities)] = module.ExportedFunction(string(setEntities))
	exportedFuncs[string(setPolicies)] = module.ExportedFunction(string(setPolicies))
	// allocate and deallocate help us manage memory in the wasm module.
	exportedFuncs[string(allocate)] = module.ExportedFunction(string(allocate))
	exportedFuncs[string(deallocate)] = module.ExportedFunction(string(deallocate))
	return exportedFuncs
}
