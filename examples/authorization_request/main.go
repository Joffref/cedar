package main

import (
	"context"
	"fmt"
	"github.com/Joffref/cedar"
)

const policies = `
permit(
  principal == User::"alice", 
  action    == Action::"update", 
  resource  == Photo::"VacationPhoto94.jpg"
);
`

const entities = `[]`

func main() {
	engine, err := cedar.NewCedarEngine(context.Background())
	if err != nil {
		panic(err)
	}
	defer engine.Close(context.Background())
	err = engine.SetEntitiesFromJson(context.Background(), entities)
	if err != nil {
		panic(err)
	}
	err = engine.SetPoliciesFromJson(context.Background(), policies)
	if err != nil {
		panic(err)
	}
	res, err := engine.Eval(context.Background(), cedar.EvalRequest{
		Principal: "User::\"alice\"",
		Action:    "Action::\"update\"",
		Resource:  "Photo::\"VacationPhoto94.jpg\"",
		Context:   "{}",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}
