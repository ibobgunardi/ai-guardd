package explain

import (
	"ai-guardd/internal/types"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLLMExplainer_Explain(t *testing.T) {
	// Mock Ollama Server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validating Request
		var req OllamaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}

		if req.Model != "test-model" {
			t.Errorf("Expected model 'test-model', got '%s'", req.Model)
		}

		// Mock Response
		resp := OllamaResponse{
			Response: "AI-generated explanation: This IP is suspicious.",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Initialize Explainer with Mock URL
	explainer := NewLLMExplainer(mockServer.URL, "test-model")

	// Create a dummy event
	evt := &types.Event{
		Source:      "ssh",
		Explanation: "",
	}

	// EXECUTE
	err := explainer.Explain(evt)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// ASSERT
	expected := "AI-generated explanation: This IP is suspicious."
	if evt.Explanation != expected {
		t.Errorf("Expected '%s', got '%s'", expected, evt.Explanation)
	}
}
