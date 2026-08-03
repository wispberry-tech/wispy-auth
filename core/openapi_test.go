package core

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestOpenAPISpecValid asserts the embedded spec is valid OpenAPI 3.0 JSON
// with a bearer security scheme and resolvable schema references.
func TestOpenAPISpecValid(t *testing.T) {
	var spec map[string]any
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	if v, _ := spec["openapi"].(string); !strings.HasPrefix(v, "3.0.") {
		t.Fatalf("openapi version = %q, want 3.0.x", v)
	}
	paths, _ := spec["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("spec has no paths")
	}
	components, _ := spec["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	if len(schemas) == 0 {
		t.Fatal("spec has no components.schemas")
	}
	securitySchemes, _ := components["securitySchemes"].(map[string]any)
	if _, ok := securitySchemes["bearerAuth"]; !ok {
		t.Fatal("spec is missing the bearerAuth security scheme")
	}

	// Every $ref into components/schemas must resolve to a defined schema.
	refRe := regexp.MustCompile(`#/components/schemas/([A-Za-z0-9_]+)`)
	for _, m := range refRe.FindAllStringSubmatch(string(openAPISpec), -1) {
		if _, ok := schemas[m[1]]; !ok {
			t.Errorf("unresolved schema $ref: %s", m[1])
		}
	}
}

// TestSpecCoversAllHandlers keeps the spec from drifting: every exported
// *AuthService method whose name ends in "Handler" must be documented via an
// x-handler operation extension, and every x-handler must name a real method.
func TestSpecCoversAllHandlers(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]struct {
			Handler string `json:"x-handler"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}

	documented := map[string]bool{}
	for path, ops := range spec.Paths {
		if len(ops) == 0 {
			t.Errorf("path %s has no operations", path)
		}
		for method, op := range ops {
			if op.Handler == "" {
				t.Errorf("operation %s %s has no x-handler", method, path)
			}
			documented[op.Handler] = true
		}
	}

	rt := reflect.TypeOf(&AuthService{})
	for i := 0; i < rt.NumMethod(); i++ {
		name := rt.Method(i).Name
		if !strings.HasSuffix(name, "Handler") {
			continue
		}
		if !documented[name] {
			t.Errorf("handler %s is not documented in openapi.json (add an operation with x-handler: %q)", name, name)
		}
	}
	for name := range documented {
		if _, ok := rt.MethodByName(name); !ok {
			t.Errorf("x-handler %q does not match any method on *AuthService", name)
		}
	}
}
