package formatter

import "testing"

func TestFormatJSONWithEmptyEntriesReturnsEmptyArray(t *testing.T) {
	output, err := FormatOutput(nil, JSONFormat)
	if err != nil {
		t.Fatalf("FormatOutput returned error: %v", err)
	}

	if output != "[]" {
		t.Fatalf("expected empty JSON array, got %q", output)
	}
}
