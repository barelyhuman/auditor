package tui

import "testing"

func TestDropNestedIDs(t *testing.T) {
	nested := map[string]map[string]bool{
		"express|4.18.2": {"qs|6.11.0": true, "send|0.18.0": true},
		"send|0.18.0":    {"mime|1.6.0": true},
	}

	got := dropNestedIDs([]string{"express|4.18.2", "qs|6.11.0", "mime|1.6.0", "lodash|4.17.21"}, nested)
	want := map[string]bool{"express|4.18.2": true, "lodash|4.17.21": true, "mime|1.6.0": true}
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	for _, id := range got {
		if !want[id] {
			t.Fatalf("unexpected %s in %v", id, got)
		}
	}
}

func TestBlockedIDs(t *testing.T) {
	nested := map[string]map[string]bool{
		"express|4.18.2": {"qs|6.11.0": true},
	}
	blocked := blockedIDs([]string{"express|4.18.2"}, nested)
	if !blocked["qs|6.11.0"] {
		t.Fatal("qs should be blocked")
	}
	if blocked["express|4.18.2"] {
		t.Fatal("parent should stay selectable")
	}
}
