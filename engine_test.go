package cedar

import (
	"context"
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
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
		t.Fatal("expected permit")
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
		t.Fatal("expected deny")
	}
}

var testSchema = `{
    "PhotoApp": {
        "commonTypes": {
            "PersonType": {
                "type": "Record",
                "attributes": {
                    "age": {
                        "type": "Long"
                    },
                    "name": {
                        "type": "String"
                    }
                }
            },
            "ContextType": {
                "type": "Record",
                "attributes": {
                    "ip": {
                        "type": "Extension",
                        "name": "ipaddr"
                    }
                }
            }
        },
        "entityTypes": {
            "User": {
                "shape": {
                    "type": "PersonType",
                    "attributes": {
                        "employeeId": {
                            "type": "String"
                        }
                    }
                },
                "memberOfTypes": [
                    "UserGroup"
                ]
            },
            "UserGroup": {
                "shape": {
                    "type": "Record",
                    "attributes": {}
                }
            },
            "Photo": {
                "shape": {
                    "type": "Record",
                    "attributes": {}
                },
                "memberOfTypes": [
                    "Album"
                ]
            },
            "Album": {
                "shape": {
                    "type": "Record",
                    "attributes": {}
                }
            }
        },
        "actions": {
            "viewPhoto": {
                "appliesTo": {
                    "principalTypes": [
                        "User",
                        "UserGroup"
                    ],
                    "resourceTypes": [
                        "Photo"
                    ],
                    "context": {
                        "type": "ContextType"
                    }
                }
            },
            "createPhoto": {
                "appliesTo": {
                    "principalTypes": [
                        "User",
                        "UserGroup"
                    ],
                    "resourceTypes": [
                        "Photo"
                    ],
                    "context": {
                        "type": "ContextType"
                    }
                }
            },
            "listPhotos": {
                "appliesTo": {
                    "principalTypes": [
                        "User",
                        "UserGroup"
                    ],
                    "resourceTypes": [
                        "Photo"
                    ],
                    "context": {
                        "type": "ContextType"
                    }
                }
            }
        }
    }
}`

var testPolicy = `permit(
    principal in PhotoApp::UserGroup::"janeFriends",
    action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
    resource in PhotoApp::Album::"janeTrips"
);`

func TestCedarEngine_ValidatePolices(t *testing.T) {
	engine, err := NewCedarEngine(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())

	tests := []struct {
		name     string
		policies string
		schema   string
		want     *ValidationResult
		wantErr  bool
	}{
		{
			name:     "valid",
			schema:   testSchema,
			policies: testPolicy,
			want: &ValidationResult{
				ValidationErrors: []ValidationError{},
			},
		},
		{
			name:     "invalid schema",
			schema:   "",
			policies: testPolicy,
			want: &ValidationResult{
				SchemaError:      StrPtr("JSON Schema file could not be parsed: EOF while parsing a value at line 1 column 0"),
				ValidationErrors: []ValidationError{},
			},
		},
		{
			name:     "invalid policy",
			schema:   testSchema,
			policies: "s",
			want: &ValidationResult{
				PolicyError:      StrPtr("\n  Unrecognized EOF found at 1\nExpected one of \"!=\", \"%\", \"&&\", \"(\", \")\", \"*\", \"+\", \",\", \"-\", \".\", \"/\", \":\", \"::\", \"<\", \"<=\", \"==\", \">\", \">=\", \"[\", \"]\", \"{\", \"||\", \"}\", ELSE, HAS, IN, LIKE or THEN"),
				ValidationErrors: []ValidationError{},
			},
		},
		{
			name:   "validation errors",
			schema: testSchema,
			policies: `permit(
				principal in NotAllowed::UserGroup::"janeFriends",
				action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
				resource in PhotoApp::Album::"janeTrips"
			);`,
			want: &ValidationResult{
				ValidationErrors: []ValidationError{
					{
						ErrorKind: "Unrecognized entity type NotAllowed::UserGroup, did you mean PhotoApp::UserGroup?",
					},
					{
						ErrorKind: "Unable to find an applicable action given the policy head constraints",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engine.ValidatePolices(context.Background(), tt.policies, tt.schema)
			if (err != nil) != tt.wantErr {
				t.Errorf("CedarEngine.ValidatePolices() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func StrPtr(s string) *string {
	return &s
}
