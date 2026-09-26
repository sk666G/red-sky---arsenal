package planner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OllamaPlanner calls a local Ollama server.
type OllamaPlanner struct {
	Host  string
	Model string
}

// NewOllama returns a planner configured for the given Ollama endpoint.
func NewOllama(host, model string) *OllamaPlanner {
	if host == "" {
		host = "http://localhost:11434"
	}
	if model == "" {
		model = "qwen2.5:1.5b"
	}
	return &OllamaPlanner{Host: host, Model: model}
}

type ollamaReq struct {
	Model   string `json:"model"`
	Prompt  string `json:"prompt"`
	Stream  bool   `json:"stream"`
	Format  string `json:"format,omitempty"`
	Options map[string]any `json:"options,omitempty"`
}

type ollamaResp struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func (o *OllamaPlanner) Plan(ctx context.Context, goal string) (*Plan, error) {
	prompt := fmt.Sprintf(SystemPrompt, goal)

	// Use format=json so qwen2.5 emits valid JSON directly.
	body := ollamaReq{
		Model:  o.Model,
		Prompt: prompt,
		Stream: false,
		Format: "json",
		Options: map[string]any{
			"temperature": 0.2,
			"num_predict": 256,
			"num_ctx":     2048,
		},
	}
	raw, _ := json.Marshal(body)

	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, "POST", o.Host+"/api/generate", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()

	var r ollamaResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("ollama decode: %w", err)
	}
	if r.Response == "" {
		return nil, ErrNoPlan
	}

	// Try the whole response first. parseTasks handles every shape:
	// array of objects, single object, array of strings, tasks-wrapper.
	if tasks, err := parseTasks(r.Response); err == nil && len(tasks) > 0 {
		return &Plan{
			Goal: goal, Backend: "ollama", Steps: tasks,
			Created: time.Now(), RawReply: r.Response,
		}, nil
	}

	// Fallback: extract the first JSON array and try again.
	if arr, err := extractJSONArray(r.Response); err == nil {
		if tasks, err := parseTasks(arr); err == nil && len(tasks) > 0 {
			return &Plan{
				Goal: goal, Backend: "ollama", Steps: tasks,
				Created: time.Now(), RawReply: r.Response,
			}, nil
		}
	}

	return &Plan{Goal: goal, Backend: "ollama", RawReply: r.Response, Created: time.Now()}, ErrNoPlan
}
