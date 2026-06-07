package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandlerServesMetrics(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body == "" {
		t.Fatal("expected metrics response body")
	}
}

func TestNewHandlerDoesNotRegisterDefaultMux(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)

	first := httptest.NewRecorder()
	NewHandler().ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first handler status = %d", first.Code)
	}

	second := httptest.NewRecorder()
	NewHandler().ServeHTTP(second, req)
	if second.Code != http.StatusOK {
		t.Fatalf("second handler status = %d", second.Code)
	}

	defaultMux := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(defaultMux, req)
	if defaultMux.Code != http.StatusNotFound {
		t.Fatalf("default mux status = %d, want %d", defaultMux.Code, http.StatusNotFound)
	}
}
