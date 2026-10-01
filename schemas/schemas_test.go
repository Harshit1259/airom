package schemas

import (
	"encoding/json"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestNativeV1IsValidJSON(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(NativeV1, &m); err != nil {
		t.Fatalf("airom-v1.schema.json is not valid JSON: %v", err)
	}
	if m["$schema"] == nil || m["$id"] == nil {
		t.Error("schema missing $schema/$id")
	}
}

// TestClosedObjectsDeclareEveryField: the schema is the published contract for
// native JSON, and the objects that set `additionalProperties: false` promise
// an exhaustive field list. Nothing validated a real document against it, so
// when the lifecycle overlay added tool.eolCatalog the schema kept rejecting
// every scan that loaded a catalog — for months, silently, because the only
// test here checked that the schema parses.
//
// This compares the field names the Go model actually serializes against the
// names the schema declares, which needs no JSON-Schema validator and fails on
// the next field somebody adds without touching this file.
func TestClosedObjectsDeclareEveryField(t *testing.T) {
	var doc struct {
		Properties map[string]struct {
			Type                 string                     `json:"type"`
			AdditionalProperties *bool                      `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(NativeV1, &doc); err != nil {
		t.Fatalf("decode schema: %v", err)
	}

	// Every field ToolInfo emits, discovered by marshaling a fully-populated
	// value rather than by listing them here — a list would drift the same way.
	toolJSON, err := json.Marshal(airom.ToolInfo{
		Name: "airom", Version: "v0", Commit: "abc",
		RulesVersion: "builtin", RulesHash: "0", EOLCatalog: "builtin",
	})
	if err != nil {
		t.Fatal(err)
	}
	var emitted map[string]json.RawMessage
	if err := json.Unmarshal(toolJSON, &emitted); err != nil {
		t.Fatal(err)
	}

	tool, ok := doc.Properties["tool"]
	if !ok {
		t.Fatal("schema has no `tool` object")
	}
	if tool.AdditionalProperties == nil || *tool.AdditionalProperties {
		t.Skip("tool no longer closes additionalProperties; this guard assumes it does")
	}
	for name := range emitted {
		if _, declared := tool.Properties[name]; !declared {
			t.Errorf("ToolInfo emits %q but the schema's `tool` object does not declare it, and closes additionalProperties: every document carrying that field fails validation", name)
		}
	}
}
