package lockfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFind(t *testing.T) {
	dir := t.TempDir()

	if _, err := Find(dir); err == nil {
		t.Fatal("expected error when no lockfile exists")
	}

	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := Find(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "package-lock.json" {
		t.Fatalf("got %s, want package-lock.json", got)
	}

	if err := os.WriteFile(filepath.Join(dir, "npm-shrinkwrap.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err = Find(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "npm-shrinkwrap.json" {
		t.Fatalf("got %s, want npm-shrinkwrap.json (npm prefers shrinkwrap)", got)
	}
}
