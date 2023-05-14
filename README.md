# Cedar Go
[![Go Report Card](https://goreportcard.com/badge/github.com/Joffref/cedar)](https://goreportcard.com/report/github.com/Joffref/cedar)
[![GoDoc](https://godoc.org/github.com/Joffref/cedar?status.svg)](https://godoc.org/github.com/Joffref/cedar)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A Go binding for the [Cedar project](https://www.cedarpolicy.com/en/) using [Wasm](https://webassembly.org/) to run the 
Cedar engine in a Go project with near zero overhead.

![Logo](assets/images/logo.png)


## Installation

```bash
go get github.com/Joffref/cedar
```

## Usage

The following example shows how to use the Cedar engine to evaluate a policy inside your Go code.

```go
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
	err = engine.SetPolicies(context.Background(), policies)
	if err != nil {
		panic(err)
	}
	res, err := engine.Eval(context.Background(), cedar.EvalRequest{
		Principal: "User::\"alice\"",
		Action:    "Action::\"update\"",
		Resource:  "Photo::\"VacationPhoto94.jpg\"",
		Context:   "{}", // Don't forget to set the context to an empty JSON object if you don't need it.
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}
```

## TODO

- [ ] Add more tests and examples.
- [ ] Add a benchmark between the Go and the Rust version.
- [ ] Support policy templates.
- [ ] Support Partial Evaluation.
- [ ] Add validation of the policy, the entities and the EvalRequest before sending them to the engine.
- ...

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the Apache License v2.0 - see the [LICENSE](LICENSE) file for details.

## Misc

This section contains some information about the project.

### Why this binding?

The [Cedar project](https://www.cedarpolicy.com/en/) is a great project but it only provides a Rust binding. 
I wanted to use it in a Go project so I decided to create this binding to embed the Cedar engine in a Go project. 
Another solution would have been to call Cedar through a REST API but I wanted to avoid the overhead of the network.

### Why Wasm?

The main reason is to avoid using [CGO](https://golang.org/cmd/cgo/) for performance reasons.
Thanks to Wasm, we can call the Cedar engine directly from Go without using CGO and with near native performance.

For more information about the considerations that led to this choice, I recommend watching
this video : [GopherCon 2022: Takeshi Yoneda - CGO-less Foreign Function Interface with WebAssembly](https://www.youtube.com/watch?v=HcRSe4Y-1Fc).

### Why not using the FFI interface provided by the Cedar project?

The FFI interface provided by the Cedar project initializes the policy and the entities store during the call to the `eval` function.
This means that if you want to evaluate multiple requests, you will have to initialize the policy and the entities store for each request.
This is not optimal if you want to evaluate a lot of requests.

This binding initializes the policy and the entities store only once and then evaluates the requests without having to reinitialize the policy and the entities store.

### Cedar affiliation

This project is not affiliated with the Cedar project, thus it is not an official binding.
