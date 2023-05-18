package cedar

import (
	"context"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"testing"
)

func Test_Allocation(t *testing.T) {
	r := wazero.NewRuntime(context.Background())
	module, err := r.Instantiate(context.Background(), cedarWasm)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("two concurrent allocation must return different ptr", func(t *testing.T) {
		twoConcurrentAllocationMustReturnDifferentPtr(t, module)
	})
	t.Run("a huge allocation must return an error", func(t *testing.T) {
		aHugeAllocationMustReturnAPtr(t, module)
	})
}

// aHugeAllocationMustReturnAPtr tests that a huge allocation mustn't return an error.
// As we use Wasm to run the Engine, we need to ensure that even if the user tries to allocate a huge amount of memory,
// memory will be allocated without crashing the process.
func aHugeAllocationMustReturnAPtr(t *testing.T, module api.Module) {
	exportedFuncs := exportFuncs(module)
	entitiesSize := uint64(1000000000) // 1GB allocation as we allocate u8 (1 byte) * size inside runtime.
	entitiesPtr, err := exportedFuncs[string(allocate)].Call(context.Background(), entitiesSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = exportedFuncs[string(deallocate)].Call(context.Background(), entitiesPtr[0], entitiesSize)
	if err != nil {
		t.Fatal("expected an error")
	}
}

func twoConcurrentAllocationMustReturnDifferentPtr(t *testing.T, module api.Module) {
	exportedFuncs := exportFuncs(module)
	entitiesSize := uint64(100)
	entitiesPtr1, err := exportedFuncs[string(allocate)].Call(context.Background(), entitiesSize)
	if err != nil {
		t.Fatal(err)
	}
	entitiesPtr2, err := exportedFuncs[string(allocate)].Call(context.Background(), entitiesSize)
	if err != nil {
		t.Fatal(err)
	}
	if entitiesPtr1[0] == entitiesPtr2[0] {
		t.Fatal("expected different pointers")
	}
	_, err = exportedFuncs[string(deallocate)].Call(context.Background(), entitiesPtr1[0], entitiesSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = exportedFuncs[string(deallocate)].Call(context.Background(), entitiesPtr2[0], entitiesSize)
	if err != nil {
		t.Fatal(err)
	}
}
