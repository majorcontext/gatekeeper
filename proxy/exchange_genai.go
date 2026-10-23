package proxy

import (
	"encoding/json"
	"strings"
)

// classifyExchange names the provider of an inference path: OpenAI Responses
// or Anthropic Messages. Any other path is not an inference request.
func classifyExchange(path string) (provider string, ok bool) {
	p := strings.ToLower(strings.TrimSuffix(path, "/"))
	switch {
	case strings.HasSuffix(p, "/v1/messages"):
		return "anthropic", true
	case strings.HasSuffix(p, "/responses"):
		return "openai", true
	}
	return "", false
}

func requestModel(body string) string {
	var v struct {
		Model string `json:"model"`
	}
	if json.Unmarshal([]byte(body), &v) != nil {
		return ""
	}
	return SanitizeLogValue(v.Model)
}

// exchangeSummary is what the events of a response say about how it ended.
type exchangeSummary struct {
	Type         string // type of the terminal event
	ResponseID   string
	FinishReason string
	Usage        string // raw usage JSON; the first and the last usage of a stream
}

type genEvent struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Status     string `json:"status"`
	StopReason string `json:"stop_reason"`
	Incomplete struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Delta struct {
		StopReason string `json:"stop_reason"`
	} `json:"delta"`
	Usage    json.RawMessage `json:"usage"`
	Response *struct {
		ID         string          `json:"id"`
		Status     string          `json:"status"`
		Usage      json.RawMessage `json:"usage"`
		Incomplete struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
	} `json:"response"`
	Message *struct {
		ID         string          `json:"id"`
		StopReason string          `json:"stop_reason"`
		Usage      json.RawMessage `json:"usage"`
	} `json:"message"`
}

var terminalTypes = map[string]bool{
	"response.completed": true, "response.incomplete": true, "response.failed": true,
	"message_delta": true, "message_stop": true, "error": true,
}

func parseEvent(data string) (genEvent, exchangeSummary, bool) {
	var ev genEvent
	if len(data) == 0 || data[0] != '{' || json.Unmarshal([]byte(data), &ev) != nil {
		return ev, exchangeSummary{}, false
	}
	s := exchangeSummary{Type: ev.Type, ResponseID: ev.ID, Usage: string(ev.Usage)}
	reason := ev.Incomplete.Reason
	status := ev.Status
	stop := firstNonEmpty(ev.Delta.StopReason, ev.StopReason)
	if r := ev.Response; r != nil {
		s.ResponseID, status, reason = firstNonEmpty(r.ID, s.ResponseID), firstNonEmpty(r.Status, status), firstNonEmpty(r.Incomplete.Reason, reason)
		s.Usage = firstNonEmpty(string(r.Usage), s.Usage)
	}
	if m := ev.Message; m != nil {
		s.ResponseID, stop = firstNonEmpty(m.ID, s.ResponseID), firstNonEmpty(m.StopReason, stop)
		s.Usage = firstNonEmpty(string(m.Usage), s.Usage)
	}
	if s.Usage == "null" {
		s.Usage = ""
	}
	switch {
	case reason != "":
		s.FinishReason = reason
	case stop != "":
		s.FinishReason = stop
	case status == "completed":
		s.FinishReason = "stop"
	case status == "failed" || ev.Type == "response.failed" || ev.Type == "error":
		s.FinishReason = "error"
	}
	return ev, s, true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// eventData returns the JSON of a stream line: an SSE data line or a bare
// object per line (WebSocket calls).
func eventData(line string) (string, bool) {
	if data, ok := strings.CutPrefix(line, "data:"); ok {
		return strings.TrimSpace(data), true
	}
	if strings.HasPrefix(line, "{") {
		return strings.TrimSpace(line), true
	}
	return "", false
}

// summarize reads a response: an event stream (the id from its first events,
// the ending from its last) or a plain JSON body.
func summarize(body string) exchangeSummary {
	lines := strings.Split(body, "\n")
	var out exchangeSummary
	var first []string
	seen := 0
	for _, line := range lines {
		data, ok := eventData(line)
		if !ok {
			continue
		}
		if _, s, ok := parseEvent(data); ok {
			if seen++; seen > 8 {
				break
			}
			out.ResponseID = firstNonEmpty(out.ResponseID, s.ResponseID)
			if s.Usage != "" {
				first = append(first, s.Usage)
			}
		}
	}
	if seen < 2 {
		if _, s, ok := parseEvent(strings.TrimSpace(body)); ok {
			return s
		}
		if seen == 0 {
			return out
		}
	}
	for i, found := len(lines)-1, 0; i >= 0 && found < 8; i-- {
		data, ok := eventData(lines[i])
		if !ok {
			continue
		}
		ev, s, ok := parseEvent(data)
		if !ok || !terminalTypes[ev.Type] {
			continue
		}
		found++
		out.Type = firstNonEmpty(out.Type, s.Type)
		out.ResponseID = firstNonEmpty(out.ResponseID, s.ResponseID)
		out.FinishReason = firstNonEmpty(out.FinishReason, s.FinishReason)
		if out.Usage == "" {
			out.Usage = s.Usage
		}
		if out.FinishReason != "" && out.Usage != "" {
			break
		}
	}
	if len(first) > 0 && first[0] != out.Usage {
		out.Usage = "[" + strings.Join(append(first[:1:1], nonEmptyList(out.Usage)...), ",") + "]"
	}
	return out
}

func nonEmptyList(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
