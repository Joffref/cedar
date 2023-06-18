package cedar

// EvalRequest is the request object for the Eval function.
// Instantion should look like this:
//
//	res, err := engine.Eval(context.Background(), cedar.EvalRequest{
//		Principal: "User::\"alice\"",
//		Action:    "Action::\"update\"",
//		Resource:  "Photo::\"VacationPhoto94.jpg\"",
//		Context:   "{}",
//	})
//
// Do not forget to add a context to the eval call in a json format and escape the quotes.
// For more information, see https://www.cedarpolicy.com/en/tutorial/abac-pt1
type EvalRequest struct {
	// Who is making the request. This is a string in the form of "User::\"alice\"".
	Principal string `json:"principal"`
	// What action is being requested. This is a string in the form of "Action::\"update\"".
	Action string `json:"action"`
	// What resource is being requested. This is a string in the form of "Photo::\"VacationPhoto94.jpg\"".
	Resource string `json:"resource"`
	// Context is a json string that can be used to pass additional information to the policy engine
	// for use in policy evaluation.
	// For more information, see https://www.cedarpolicy.com/en/tutorial/context
	Context string `json:"context"`
}

// EvalResponse is the response issued by the Eval function when in JSON Eval mode.
type EvalResponse struct {
	// Decision is the result of the policy evaluation.
	Decision EvalResult `json:"decision"`
	// Diagnostics is the diagnostic information returned by the policy engine when an evaluation is made.
	Diagnostics Diagnostic `json:"diagnostics"`
}

// Diagnostic represents the diagnostic information returned by the policy engine when an evaluation is made.
type Diagnostic struct {
	// Reason is the list of policies that caused the decision.
	Reason []string `json:"reason"`
	// Errors is the list of errors that occurred during evaluation.
	Errors []string `json:"errors"`
}

// EvalResult is the response object for the Eval function.
type EvalResult string

const (
	EvalResultPermit EvalResult = "Allow"
	EvalResultDeny   EvalResult = "Deny"
)

func (e EvalResult) String() string {
	return string(e)
}

func (e EvalResult) IsPermit() bool {
	return e == EvalResultPermit
}
