package server

import "testing"

func TestServerVersionUsesBuildVersion(t *testing.T) {
	saved := buildVersion
	t.Cleanup(func() { buildVersion = saved })

	buildVersion = "v2.5.1"
	if got := serverVersion(); got != "2.5.1" {
		t.Fatalf("serverVersion() = %q, want 2.5.1", got)
	}
	buildVersion = ""
	if got := serverVersion(); got == "" {
		t.Fatal("serverVersion() is empty without a build version")
	}
}
