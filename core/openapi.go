package core

import (
	_ "embed"
	"log/slog"
	"net/http"
)

//go:embed openapi.json
var openAPISpec []byte

// OpenAPIHandler serves the OpenAPI 3.0 specification of the built-in
// authentication endpoints as JSON. Mount it on any router, e.g.:
//
//	mux.Handle("GET /swagger/doc.json", core.OpenAPIHandler())
//
// The spec documents the endpoints at their canonical paths (see the endpoint
// table in the README); wire the handlers to those paths so the spec matches
// your server. Point any OpenAPI viewer (Swagger UI, Redoc, Scalar) at the
// served URL.
//
// Each operation carries an x-handler extension naming its AuthService
// method; TestSpecCoversAllHandlers fails if a handler is added without
// documentation or an operation names a method that no longer exists.
func OpenAPIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(openAPISpec); err != nil {
			slog.Debug("Failed to write OpenAPI spec", "error", err)
		}
	})
}
