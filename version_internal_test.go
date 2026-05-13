package arksdk

import (
	"regexp"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadSDKVersionFrom(t *testing.T) {
	// modulePath is what the SDK's go.mod declares — both Main and Deps
	// matches key on it. We pin it explicitly in each fixture rather than
	// reading the constant, so a stray rename of modulePath without
	// updating these tests doesn't silently keep them green.
	const path = "github.com/arkade-os/go-sdk"

	cases := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{
			name: "nil build info",
			info: nil,
			want: "unknown",
		},
		{
			name: "SDK is the main module without a version (devel)",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: path, Version: ""},
			},
			want: "(devel)",
		},
		{
			name: "SDK is the main module with a tagged version",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: path, Version: "v1.4.2"},
			},
			want: "v1.4.2",
		},
		{
			name: "SDK is the main module with a pseudo-version",
			info: &debug.BuildInfo{
				Main: debug.Module{
					Path:    path,
					Version: "v0.0.0-20260513120000-abc1234def56",
				},
			},
			want: "v0.0.0-20260513120000-abc1234def56",
		},
		{
			name: "SDK is a dependency at a tagged version",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/some/importer"},
				Deps: []*debug.Module{
					{Path: "github.com/other/dep", Version: "v0.1.0"},
					{Path: path, Version: "v1.4.2"},
				},
			},
			want: "v1.4.2",
		},
		{
			name: "SDK is a dependency at a pseudo-version",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/some/importer"},
				Deps: []*debug.Module{
					{Path: path, Version: "v0.0.0-20260513120000-abc1234def56"},
				},
			},
			want: "v0.0.0-20260513120000-abc1234def56",
		},
		{
			name: "importing binary doesn't depend on the SDK",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/some/importer"},
				Deps: []*debug.Module{
					{Path: "github.com/other/dep", Version: "v0.1.0"},
				},
			},
			want: "unknown",
		},
		{
			name: "importing binary has no deps recorded",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/some/importer"},
			},
			want: "unknown",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := readSDKVersionFrom(tc.info)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestVersionPackageVarIsResolved asserts that the package-level Version
// variable is one of the four recognized shapes. We can't pin a specific
// value (it depends on how the test binary was built — typically "(devel)"
// when running `go test ./...` from inside the repo), but we can refuse
// outright garbage such as an empty string or a random unrelated literal.
func TestVersionPackageVarIsResolved(t *testing.T) {
	require.NotEmpty(t, Version, "Version must be populated by package init")

	switch {
	case Version == "(devel)":
		// Most common case when running tests from this repo.
	case Version == "unknown":
		// Acceptable on toolchains / harnesses without build info.
	case semverPattern.MatchString(Version):
		// e.g. v1.4.2 or v1.4.2-rc.1.
	case pseudoVersionPattern.MatchString(Version):
		// e.g. v0.0.0-20260513120000-abc1234def56.
	default:
		t.Fatalf("Version %q does not match any recognized shape", Version)
	}
}

// Loose patterns — we're checking shape, not validating semver strictly.
// pkg.go.dev's accepted forms are documented at
// https://go.dev/ref/mod#pseudo-versions, but for this test "looks like
// a valid version" is enough.
var (
	semverPattern        = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[\w.-]+)?(\+[\w.-]+)?$`)
	pseudoVersionPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+-(?:.+-)?\d{14}-[0-9a-f]{12}$`)
)
