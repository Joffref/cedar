package cedar

import (
	"context"
	"testing"
)

func TestCedarEngine_FFI(t *testing.T) {
	ctx := context.Background()
	engine, err := NewCedarEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(ctx)
	t.Run("ffi must return deny", func(t *testing.T) {
		ffiMustReturnDeny(t, engine, `
		{
			"principal": "User::\"alice\"",
			"action": "Photo::\"view\"",
			"resource": "Photo::\"photo\"",
			"slice": {
			"policies": {},
			"entities": []
		},
		"context": {}
	}`)
	})
	t.Run("ffi must return error if json is not serializable", func(t *testing.T) {
		ffiMustReturnErrorIfJsonIsNotSerializable(t, engine, `
		{
			"principal": "User::\"alice\"",
			"action": "Photo::\"view\"",
	}`)
	})
	t.Run("ffi must return allow", func(t *testing.T) {
		ffiMustReturnAllow(t, engine, `
		        {
            "context": {},
            "slice": {
              "policies": {
                "001": "permit(principal, action, resource);"
              },
              "entities": [],
              "templates": {},
              "template_instantiations": []
            },
            "principal": "User::\"alice\"",
            "action": "Action::\"view\"",
            "resource": "Resource::\"thing\""
        }`)
	})
}

func ffiMustReturnDeny(t *testing.T, engine *CedarEngine, input string) {
	ctx := context.Background()
	res, err := engine.FFI(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if res.Result.Decision.IsPermit() {
		t.Fatal("expected Deny")
	}
}

func ffiMustReturnErrorIfJsonIsNotSerializable(t *testing.T, engine *CedarEngine, input string) {
	ctx := context.Background()
	res, err := engine.FFI(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) == 0 {
		t.Fatal("expected error")
	}
}

func ffiMustReturnAllow(t *testing.T, engine *CedarEngine, input string) {
	ctx := context.Background()
	res, err := engine.FFI(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Result.Decision.IsPermit() {
		t.Fatal("expected Allow")
	}
}
