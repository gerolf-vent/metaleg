package controller

import (
	"fmt"
	"go/build"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	metallbv1beta1 "go.universe.tf/metallb/api/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const (
	metallbSL2SCRDURL = "https://raw.githubusercontent.com/metallb/metallb/v0.15.3/config/crd/bases/metallb.io_servicel2statuses.yaml"
)

var (
	cfg        *rest.Config
	testScheme *runtime.Scheme
)

// fetchCRD downloads a CRD YAML from url and caches it under cacheDir.
// Returns the local file path.
func fetchCRD(url, cacheDir string) (string, error) {
	filename := filepath.Base(url)
	dest := filepath.Join(cacheDir, filename)

	if _, err := os.Stat(dest); err == nil {
		return dest, nil // already cached
	}

	resp, err := http.Get(url) //#nosec G107 -- URL is a compile-time constant
	if err != nil {
		return "", fmt.Errorf("failed to fetch CRD from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d fetching CRD from %s", resp.StatusCode, url)
	}

	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return "", fmt.Errorf("failed to create CRD cache dir: %w", err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read CRD body: %w", err)
	}

	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return "", fmt.Errorf("failed to write CRD file: %w", err)
	}

	return dest, nil
}

func TestMain(m *testing.M) {
	os.Setenv("PATH", fmt.Sprintf("%s/bin:%s", build.Default.GOPATH, os.Getenv("PATH")))

	// Call setup-envtest
	out, err := exec.Command("setup-envtest", "use", "-p", "path").Output()
	if err != nil {
		log.Fatalf("failed to setup test environment: %v", err)
	}
	os.Setenv("KUBEBUILDER_ASSETS", strings.TrimSpace(string(out)))

	// Fetch and cache MetalLB CRDs
	crdCacheDir := filepath.Join(os.TempDir(), "metaleg-test-crds")
	crdPath, err := fetchCRD(metallbSL2SCRDURL, crdCacheDir)
	if err != nil {
		log.Fatalf("failed to fetch MetalLB CRD: %v", err)
	}

	// Build client scheme
	testScheme = runtime.NewScheme()
	if err := scheme.AddToScheme(testScheme); err != nil {
		log.Fatalf("failed to add k8s scheme: %v", err)
	}
	if err := metallbv1beta1.AddToScheme(testScheme); err != nil {
		log.Fatalf("failed to add metallb v1beta1 scheme: %v", err)
	}

	// Create test environment with MetalLB CRDs
	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Dir(crdPath)},
		Scheme:            testScheme,
	}

	// Start test environment
	cfg, err = testEnv.Start()
	if err != nil {
		log.Fatalf("failed to start test environment: %v", err)
	}

	// Run all tests, capture exit code
	code := m.Run()

	os.Exit(code) // must call this, or the process won't exit with the right code
}
