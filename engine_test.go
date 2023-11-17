package cedar

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCedarEngine_IsAuthorized(t *testing.T) {
	policy := `
	permit(
		principal == User::"alice",
		action    == Action::"update",
		resource  == Photo::"VacationPhoto94.jpg"
	);
	`
	engine, err := NewCedarEngine(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	err = engine.SetEntitiesFromJson(context.Background(), "[]")
	if err != nil {
		t.Fatal(err)
	}
	err = engine.SetPolicies(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("is authorized must return allow", func(t *testing.T) {
		isAuthorizedMustReturnAllow(t, engine, "User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto94.jpg\"")
	})
	t.Run("is authorized must return deny", func(t *testing.T) {
		isAuthorizedMustReturnDeny(t, engine, "User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto95.jpg\"")
	})
}
func isAuthorizedMustReturnAllow(t *testing.T, engine *CedarEngine, principal, action, resource string) {
	res, err := engine.IsAuthorized(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("expected Allow")
	}
}

func isAuthorizedMustReturnDeny(t *testing.T, engine *CedarEngine, principal, action, resource string) {
	res, err := engine.IsAuthorized(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res {
		t.Fatal("expected Deny")
	}
}

func TestCedarEngine_EvalWithResponse(t *testing.T) {
	policy := `
	permit(
		principal == User::"alice",
		action    == Action::"update",
		resource  == Photo::"VacationPhoto94.jpg"
	);
	`
	engine, err := NewCedarEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	err = engine.SetEntitiesFromJson(context.Background(), "[]")
	if err != nil {
		t.Fatal(err)
	}
	err = engine.SetPolicies(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("eval with response must return allow", func(t *testing.T) {
		evalJSONMustReturnAllow(t, engine, "User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto94.jpg\"")
	})
	t.Run("eval with response must return deny", func(t *testing.T) {
		evalJSONMustReturnDeny(t, engine, "User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto95.jpg\"")
	})
}

func evalJSONMustReturnAllow(t *testing.T, engine *CedarEngine, principal, action, resource string) {
	res, err := engine.EvalWithResponse(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != "Allow" {
		t.Fatal("expected Allow")
	}
	if res.Diagnostics.Reason[0] != "policy0" { // First policy as it is the only one. Cedar engine fixes the policy name to policy<number> if not provided.
		t.Fatal("expected policy0 to be the reason for the decision")
	}
	if len(res.Diagnostics.Errors) != 0 {
		t.Fatal("expected no errors")
	}
}

func evalJSONMustReturnDeny(t *testing.T, engine *CedarEngine, principal, action, resource string) {
	res, err := engine.EvalWithResponse(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != "Deny" {
		t.Fatal("expected Deny")
	}
	if len(res.Diagnostics.Reason) != 0 {
		t.Fatal("expected no reason for the decision")
	}
	if len(res.Diagnostics.Errors) != 0 {
		t.Fatal("expected no errors")
	}
}

func TestCedarEngine_IsAuthorizedPartialTemplate(t *testing.T) {
	policy := `
	permit(
		principal == User::"alice",
		action    == Action::"update",
		resource  == Photo::"VacationPhoto94.jpg"
	);
	`
	engine, err := NewCedarEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	err = engine.SetEntitiesFromJson(context.Background(), "[]")
	if err != nil {
		t.Fatal(err)
	}
	err = engine.SetPolicies(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("is authorized partial must return allow", func(t *testing.T) {
		isAuthorizedPartialMustReturnAllow(t, engine, "User::\"alice\"", "Action::\"update\"",
			"Photo::\"VacationPhoto94.jpg\"", "{}")
	})
	t.Run("is authorized partial must return deny", func(t *testing.T) {
		isAuthorizedPartialMustReturnDeny(t, engine, "User::\"alice\"", "Action::\"update\"",
			"Photo::\"VacationPhoto95.jpg\"", "{}")
	})
	t.Run("is authorized partial with missing principal must return residual", func(t *testing.T) {
		isAuthorizedPartialMustReturnResidual(t, engine, "", "Action::\"update\"",
			"Photo::\"VacationPhoto95.jpg\"", "{}")
	})
	t.Run("is authorized partial with missing action must return residual", func(t *testing.T) {
		isAuthorizedPartialMustReturnResidual(t, engine, "User::\"alice\"", "",
			"Photo::\"VacationPhoto95.jpg\"", "{}")
	})
	t.Run("is authorized partial with missing resource must return residual", func(t *testing.T) {
		isAuthorizedPartialMustReturnResidual(t, engine, "User::\"alice\"", "Action::\"update\"",
			"", "{}")
	})
}

func TestCedarEngine_IsAuthorizedPartialCondition(t *testing.T) {
	policy := `
	permit(principal, action, resource)
	when {
		principal == User::"alice" && 
		action == Action::"update" && 
		resource  == Photo::"VacationPhoto94.jpg" &&
        context.test == "foo"
	};
	`
	engine, err := NewCedarEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	err = engine.SetEntitiesFromJson(context.Background(), "[]")
	if err != nil {
		t.Fatal(err)
	}
	err = engine.SetPolicies(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("is authorized partial must return allow", func(t *testing.T) {
		isAuthorizedPartialMustReturnAllow(t, engine, "User::\"alice\"", "Action::\"update\"",
			"Photo::\"VacationPhoto94.jpg\"", "{\"test\":\"foo\"}")
	})
	t.Run("is authorized partial must return deny", func(t *testing.T) {
		isAuthorizedPartialMustReturnDeny(t, engine, "User::\"alice\"", "Action::\"update\"",
			"Photo::\"VacationPhoto95.jpg\"", "{\"test\":\"foo\"}")
	})
	t.Run("is authorized partial with no principal must return residual", func(t *testing.T) {
		isAuthorizedPartialMustReturnResidual(t, engine, "f", "Action::\"update\"",
			"Photo::\"VacationPhoto95.jpg\"", "{\"test\":\"foo\"}")
	})
	t.Run("is authorized partial with no action must return residual", func(t *testing.T) {
		isAuthorizedPartialMustReturnResidual(t, engine, "User::\"alice\"", "",
			"", "{\"test\":\"foo\"}")
	})
	t.Run("is authorized partial with no resource must return residual", func(t *testing.T) {
		isAuthorizedPartialMustReturnResidual(t, engine, "User::\"alice\"", "Action::\"update\"",
			"", "{\"test\":\"foo\"}")
	})
	t.Run("is authorized partial with missing context attribute must return residual", func(t *testing.T) {
		isAuthorizedPartialMustReturnResidual(t, engine, "User::\"alice\"", "Action::\"update\"",
			"", "{}")
	})
}

func isAuthorizedPartialMustReturnAllow(t *testing.T, engine *CedarEngine, principal, action, resource, jsonContext string) {
	resJson, err := engine.IsAuthorizedPartial(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   jsonContext,
	})
	if err != nil {
		t.Fatal(err)
	}

	var res = EvalResponse{}
	err2 := json.Unmarshal([]byte(resJson), &res)
	if err2 != nil {
		t.Fatal(err2)
	}

	if res.Decision != "Allow" {
		t.Fatal("expected Allow")
	}
	if res.Diagnostics.Reason[0] != "policy0" { // First policy as it is the only one. Cedar engine fixes the policy name to policy<number> if not provided.
		t.Fatal("expected policy0 to be the reason for the decision")
	}
	if len(res.Diagnostics.Errors) != 0 {
		t.Fatal("expected no errors")
	}
}

func isAuthorizedPartialMustReturnDeny(t *testing.T, engine *CedarEngine, principal, action, resource, jsonContext string) {
	resJson, err := engine.IsAuthorizedPartial(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   jsonContext,
	})
	if err != nil {
		t.Fatal(err)
	}

	var res = EvalResponse{}
	err2 := json.Unmarshal([]byte(resJson), &res)
	if err2 != nil {
		t.Fatal(err2)
	}

	if res.Decision != "Deny" {
		t.Fatal("expected Deny")
	}
	if len(res.Diagnostics.Reason) != 0 {
		t.Fatal("expected no reason for the decision")
	}
	if len(res.Diagnostics.Errors) != 0 {
		t.Fatal("expected no errors")
	}
}

func isAuthorizedPartialMustReturnResidual(t *testing.T, engine *CedarEngine, principal, action, resource, jsonContext string) {
	resJson, err := engine.IsAuthorizedPartial(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   jsonContext,
	})
	if err != nil {
		t.Fatal(err)
	}

	// TODO: need a new struct for partial results
	var res = EvalResponse{}
	err2 := json.Unmarshal([]byte(resJson), &res)
	if err2 != nil {
		t.Fatal(err2, " -- ", resJson)
	}

	println("resJson = {}", resJson)
}
