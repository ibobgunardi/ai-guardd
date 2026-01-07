package explain

import (
	"ai-guardd/internal/types"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LLMExplainer uses a local LLM (e.g., Ollama) to generate explanations
type LLMExplainer struct {
	url    string
	model  string
	client *http.Client
}

func NewLLMExplainer(url, model string) *LLMExplainer {
	if url == "" {
		url = "http://localhost:11434/api/generate"
	}
	if model == "" {
		model = "tinyllama" // Default lightweight model
	}
	return &LLMExplainer{
		url:   url,
		model: model,
		client: &http.Client{
			Timeout: 10 * time.Second, // Don't block too long
		},
	}
}

// OllamaRequest represents the payload for Ollama
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// OllamaResponse represents the response from Ollama
type OllamaResponse struct {
	Response string `json:"response"`
}

func (e *LLMExplainer) Explain(event *types.Event) error {
	prompt := e.buildPrompt(event)

	reqBody := OllamaRequest{
		Model:  e.model,
		Prompt: prompt,
		Stream: false,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal llm request: %w", err)
	}

	resp, err := e.client.Post(e.url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		// Soft failure: log error but don't crash, return error so caller can fallback
		return fmt.Errorf("llm connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("llm returned status: %s", resp.Status)
	}

	var llmResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return fmt.Errorf("failed to decode llm response: %w", err)
	}

	// Update the event with the generated explanation
	event.Explanation = llmResp.Response
	return nil
}

func (e *LLMExplainer) buildPrompt(event *types.Event) string {
	return fmt.Sprintf(`You are a security analyst. specificly explain the risk of this event in 1 sentence.
Event: %s
Source: %s
Risk: %s
Details: %s
Evidence: %v
Explanation:`, event.Summary, event.Source, event.Risk, event.Explanation, event.Evidence)
}
