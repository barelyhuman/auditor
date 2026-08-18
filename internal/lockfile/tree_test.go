package lockfile

import "testing"

func TestTransitives(t *testing.T) {
	lock := PackageLock{
		LockfileVersion: 3,
		Packages: map[string]LockedPackage{
			"": {Dependencies: map[string]string{"express": "4.18.2", "qs": "6.11.0"}},
			"node_modules/express": {
				Version:      "4.18.2",
				Dependencies: map[string]string{"qs": "6.11.0", "send": "0.18.0"},
			},
			"node_modules/qs":    {Version: "6.11.0"},
			"node_modules/send":  {Version: "0.18.0", Dependencies: map[string]string{"mime": "1.6.0"}},
			"node_modules/mime":  {Version: "1.6.0"},
			"node_modules/other": {Version: "1.0.0"},
		},
	}

	tree := transitives(lock)

	express := tree["express|4.18.2"]
	if !express["qs|6.11.0"] || !express["send|0.18.0"] || !express["mime|1.6.0"] {
		t.Fatalf("express transitives = %v", express)
	}
	if express["other|1.0.0"] {
		t.Fatal("other is not under express")
	}
	if !tree["send|0.18.0"]["mime|1.6.0"] {
		t.Fatal("mime should be transitive of send")
	}
	if tree["qs|6.11.0"]["express|4.18.2"] {
		t.Fatal("qs should not list express")
	}
}

func TestResolveNestedInstall(t *testing.T) {
	lock := PackageLock{
		LockfileVersion: 3,
		Packages: map[string]LockedPackage{
			"node_modules/a": {
				Version:      "1.0.0",
				Dependencies: map[string]string{"b": "2.0.0"},
			},
			"node_modules/a/node_modules/b": {Version: "2.0.0"},
			"node_modules/b":                {Version: "1.0.0"},
		},
	}
	tree := transitives(lock)
	if !tree["a|1.0.0"]["b|2.0.0"] {
		t.Fatalf("nested b@2 should win, got %v", tree["a|1.0.0"])
	}
	if tree["a|1.0.0"]["b|1.0.0"] {
		t.Fatal("hoisted b@1 is not a's install")
	}
}
