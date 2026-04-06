package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
)

var version = "dev"

const (
	defaultKey       = "~/.ssh/id_ed25519_sk"
	defaultNamespace = "file"
	defaultAgeSlot   = "1"
	maxPubkeySize    = 8192
)

var dangerousSSHEnvVars = []string{
	"SSH_AUTH_SOCK",
	"SSH_SK_PROVIDER",
	"SSH_ASKPASS",
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		requireCmd("ssh-keygen")
		cmdKeygen(os.Args[2:])
	case "sign":
		requireCmd("ssh-keygen")
		cmdSign(os.Args[2:])
	case "verify":
		requireCmd("ssh-keygen")
		cmdVerify(os.Args[2:])
	case "age-keygen":
		requireCmd("age-plugin-yubikey")
		cmdAgeKeygen(os.Args[2:])
	case "age-list":
		die("removed — run 'age-plugin-yubikey --list' directly, or see 'sear help yubikey'")
	case "age-identity":
		die("removed — run 'age-plugin-yubikey --identity' directly, or see 'sear help yubikey'")
	case "seal":
		requireCmd("age")
		requireCmd("ssh-keygen")
		cmdSeal(os.Args[2:])
	case "unseal":
		requireCmd("age")
		requireCmd("ssh-keygen")
		cmdUnseal(os.Args[2:])
	case "encrypt":
		requireCmd("age")
		cmdEncrypt(os.Args[2:])
	case "decrypt":
		requireCmd("age")
		cmdDecrypt(os.Args[2:])
	case "version", "--version", "-V":
		fmt.Printf("sear %s\n", version)
	case "help", "--help", "-h":
		if len(os.Args) > 2 {
			helpTopic(os.Args[2])
		} else {
			usage()
		}
	default:
		die("unknown command: %s", os.Args[1])
	}
}

func requireCmd(name string) {
	if _, err := exec.LookPath(name); err != nil {
		die("%s is required but not found in PATH", name)
	}
}

// ── keygen ──────────────────────────────────────────────────────────

func cmdKeygen(args []string) {
	if len(args) == 0 {
		usageKeygen()
		os.Exit(1)
	}

	keyPath := expandHome(defaultKey)
	comment := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f":
			i++
			if i >= len(args) {
				die("-f requires an argument")
			}
			keyPath = expandHome(args[i])
		case "-C":
			i++
			if i >= len(args) {
				die("-C requires an argument")
			}
			comment = args[i]
		case "-h", "--help":
			usageKeygen()
			os.Exit(0)
		default:
			die("unexpected argument: %s", args[i])
		}
	}

	if comment == "" {
		die("-C is required (names the key on disk and on the YubiKey)")
	}
	app := "ssh:" + comment

	if _, err := os.Stat(keyPath); err == nil {
		die("key already exists: %s (remove it first if you want to regenerate)", keyPath)
	}

	step("Generating ed25519-sk key (PIN + touch required)")
	cmd := exec.Command("ssh-keygen",
		"-t", "ed25519-sk",
		"-O", "resident",
		"-O", "verify-required",
		"-O", "application="+app,
		"-f", keyPath,
		"-C", comment,
		"-N", "",
	)
	cmd.Env = cleanEnv(os.Environ())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	logCmd(cmd)

	if err := cmd.Run(); err != nil {
		die("key generation failed")
	}

	step("Key created")
	fmt.Fprintf(os.Stderr, "  Private: %s\n", keyPath)
	fmt.Fprintf(os.Stderr, "  Public:  %s.pub\n", keyPath)
}

// ── age-keygen ──────────────────────────────────────────────────────

func cmdAgeKeygen(args []string) {
	slot := defaultAgeSlot
	output := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-s":
			i++
			if i >= len(args) {
				die("-s requires an argument")
			}
			slot = args[i]
		case "-o":
			i++
			if i >= len(args) {
				die("-o requires an argument")
			}
			output = expandHome(args[i])
		case "-h", "--help":
			usageAgeKeygen()
			os.Exit(0)
		default:
			die("unexpected argument: %s", args[i])
		}
	}

	step("Generating age key on YubiKey (PIN + touch required)")
	cmdArgs := []string{"--generate", "--slot", slot, "--pin-policy", "always", "--touch-policy", "always"}
	cmd := exec.Command("age-plugin-yubikey", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	logCmd(cmd)

	// Capture stdout to parse recipient and identity from plugin output
	out, err := cmd.Output()
	if err != nil {
		die("age key generation failed")
	}

	// Parse recipient and identity from stdout
	var recipient, identity string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			if _, after, ok := strings.Cut(line, "Recipient: "); ok {
				recipient = strings.TrimSpace(after)
			}
		} else if strings.HasPrefix(line, "age1yubikey1") {
			recipient = line
		} else if strings.HasPrefix(line, "AGE-PLUGIN-YUBIKEY-") {
			identity = line
		}
	}

	// Also check for identity file written to disk (older plugin versions)
	identityFile := findLatestIdentityFile()
	if identityFile != "" {
		if recipient == "" {
			recipient = parseRecipientFromIdentity(identityFile)
		}
		if output != "" {
			if err := moveFile(identityFile, output); err != nil {
				fmt.Fprintf(os.Stderr, "sear: could not move identity file to %s: %v\n", output, err)
			}
		}
	}

	// Write identity file from captured output if no file was created
	if identity != "" && identityFile == "" && output != "" {
		content := fmt.Sprintf("# created: %s\n", time.Now().Format(time.RFC3339))
		if recipient != "" {
			content += fmt.Sprintf("# recipient: %s\n", recipient)
		}
		content += identity + "\n"
		if err := os.WriteFile(output, []byte(content), 0600); err != nil {
			die("failed to write identity file: %v", err)
		}
	}

	step("Age key created")
	if recipient != "" {
		fmt.Fprintf(os.Stderr, "  Recipient: %s\n", recipient)
		fmt.Printf("%s\n", recipient) // stdout for scripting
	}
	if identity != "" {
		fmt.Fprintf(os.Stderr, "  Identity:  %s\n", identity)
	}
	if output != "" {
		fmt.Fprintf(os.Stderr, "  Saved to:  %s\n", output)
	}
	fmt.Fprintf(os.Stderr, "  Slot:      %s\n", slot)
	fmt.Fprintf(os.Stderr, "  Policy:    PIN always, touch always\n")

	step("Done")
	fmt.Fprintf(os.Stderr, "  Add recipient to ~/.age-recipients for multi-key encryption.\n")
	fmt.Fprintf(os.Stderr, "  Keep the identity file safe — needed for decryption.\n")
}

// ── seal (encrypt + sign) ────────────────────────────────────────────

func cmdSeal(args []string) {
	var recipients []string
	var recipientFiles []string
	armor := false
	key := ""
	namespace := defaultNamespace
	var files []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-r":
			i++
			if i >= len(args) {
				die("-r requires an argument")
			}
			recipients = append(recipients, args[i])
		case "-R":
			i++
			if i >= len(args) {
				die("-R requires an argument")
			}
			recipientFiles = append(recipientFiles, expandHome(args[i]))
		case "-a":
			armor = true
		case "-k":
			i++
			if i >= len(args) {
				die("-k requires an argument")
			}
			key = args[i]
		case "-n":
			i++
			if i >= len(args) {
				die("-n requires an argument")
			}
			namespace = args[i]
		case "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case "-h", "--help":
			usageSeal()
			os.Exit(0)
		default:
			files = append(files, args[i])
		}
	}

	if len(files) == 0 {
		die("no files specified")
	}
	if len(recipients) == 0 && len(recipientFiles) == 0 {
		die("no recipients specified (use -r or -R)")
	}
	if !validNamespace(namespace) {
		die("invalid namespace: must be non-empty with no whitespace")
	}

	if key == "" {
		key = defaultKey
	}
	key = expandHome(key)
	if _, err := os.Stat(key); err != nil {
		die("signing key not found: %s", key)
	}

	errors := 0
	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			fmt.Fprintf(os.Stderr, "sear: file not found: %s\n", file)
			errors++
			continue
		}

		// Encrypt
		agePath := file + ".age"
		cmdArgs := []string{}
		for _, r := range recipients {
			cmdArgs = append(cmdArgs, "-r", r)
		}
		for _, rf := range recipientFiles {
			cmdArgs = append(cmdArgs, "-R", rf)
		}
		if armor {
			cmdArgs = append(cmdArgs, "-a")
		}
		cmdArgs = append(cmdArgs, "-o", agePath, "--", file)

		encCmd := exec.Command("age", cmdArgs...)
		encCmd.Stdin = os.Stdin
		encCmd.Stderr = os.Stderr
		logCmd(encCmd)

		if err := encCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "sear: encryption failed: %s\n", file)
			errors++
			continue
		}

		// Sign the encrypted file
		sigPath := agePath + ".sig"
		safeRemove(sigPath)

		signCmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", key, "-n", namespace, "--", agePath)
		signCmd.Env = cleanEnv(os.Environ())
		signCmd.Stdin = os.Stdin
		signCmd.Stderr = os.Stderr
		logCmd(signCmd)

		if err := signCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "sear: signing failed: %s\n", agePath)
			errors++
			continue
		}

		fmt.Printf("OK: %s -> %s + %s\n", file, agePath, sigPath)
	}

	if errors > 0 {
		os.Exit(1)
	}
}

// ── unseal (verify + decrypt) ───────────────────────────────────────

func cmdUnseal(args []string) {
	var identities []string
	pubkey := ""
	namespace := defaultNamespace
	output := ""
	var files []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			i++
			if i >= len(args) {
				die("-i requires an argument")
			}
			identities = append(identities, expandHome(args[i]))
		case "-p":
			i++
			if i >= len(args) {
				die("-p requires an argument")
			}
			pubkey = args[i]
		case "-n":
			i++
			if i >= len(args) {
				die("-n requires an argument")
			}
			namespace = args[i]
		case "-o":
			i++
			if i >= len(args) {
				die("-o requires an argument")
			}
			output = expandHome(args[i])
		case "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case "-h", "--help":
			usageUnseal()
			os.Exit(0)
		default:
			files = append(files, args[i])
		}
	}

	if len(files) == 0 {
		die("no files specified")
	}
	if len(identities) == 0 {
		die("no identity specified (use -i)")
	}
	if !validNamespace(namespace) {
		die("invalid namespace: must be non-empty with no whitespace")
	}
	if output != "" && len(files) > 1 {
		die("-o can only be used with a single file")
	}

	// Resolve public key(s) for verification
	pubkeys, err := resolvePubkeys(pubkey)
	if err != nil {
		die("%v", err)
	}

	tmp, err := os.CreateTemp("", "sear-signers-*")
	if err != nil {
		die("failed to create temp file: %v", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Remove(tmpPath)
		os.Exit(1)
	}()

	for _, key := range pubkeys {
		fmt.Fprintf(tmp, "sear %s\n", key)
	}
	tmp.Close()

	errors := 0
	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			fmt.Fprintf(os.Stderr, "sear: file not found: %s\n", file)
			errors++
			continue
		}

		// Verify
		sigFile := file + ".sig"
		if _, err := os.Stat(sigFile); err != nil {
			fmt.Fprintf(os.Stderr, "sear: signature not found: %s\n", sigFile)
			errors++
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sear: cannot open %s: %v\n", file, err)
			errors++
			continue
		}

		verifyCmd := exec.Command("ssh-keygen", "-Y", "verify",
			"-f", tmpPath,
			"-I", "sear",
			"-n", namespace,
			"-s", sigFile,
		)
		verifyCmd.Stdin = f
		logCmd(verifyCmd)
		vOut, vErr := verifyCmd.CombinedOutput()
		f.Close()

		if vErr != nil {
			fmt.Fprintf(os.Stderr, "sear: FAIL: %s\n", file)
			if lines := strings.SplitN(string(vOut), "\n", 2); len(lines) > 0 && lines[0] != "" {
				fmt.Fprintf(os.Stderr, "  %s\n", lines[0])
			}
			errors++
			continue
		}

		// Decrypt
		outPath := output
		if outPath == "" {
			outPath = strings.TrimSuffix(file, ".age")
			if outPath == file {
				outPath = file + ".dec"
			}
		}

		decArgs := []string{"-d"}
		for _, id := range identities {
			decArgs = append(decArgs, "-i", id)
		}
		decArgs = append(decArgs, "-o", outPath, "--", file)

		decCmd := exec.Command("age", decArgs...)
		decCmd.Stdin = os.Stdin
		decCmd.Stderr = os.Stderr
		logCmd(decCmd)

		if err := decCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "sear: decryption failed: %s\n", file)
			errors++
			continue
		}

		fmt.Printf("OK: %s -> %s (verified + decrypted)\n", file, outPath)
	}

	signal.Stop(sigCh)

	if errors > 0 {
		os.Exit(1)
	}
}

// ── encrypt ─────────────────────────────────────────────────────────

func cmdEncrypt(args []string) {
	var recipients []string
	var recipientFiles []string
	armor := false
	output := ""
	var files []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-r":
			i++
			if i >= len(args) {
				die("-r requires an argument")
			}
			recipients = append(recipients, args[i])
		case "-R":
			i++
			if i >= len(args) {
				die("-R requires an argument")
			}
			recipientFiles = append(recipientFiles, expandHome(args[i]))
		case "-a":
			armor = true
		case "-o":
			i++
			if i >= len(args) {
				die("-o requires an argument")
			}
			output = expandHome(args[i])
		case "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case "-h", "--help":
			usageEncrypt()
			os.Exit(0)
		default:
			files = append(files, args[i])
		}
	}

	if len(files) == 0 {
		die("no files specified")
	}
	if len(recipients) == 0 && len(recipientFiles) == 0 {
		die("no recipients specified (use -r or -R)")
	}
	if output != "" && len(files) > 1 {
		die("-o can only be used with a single file")
	}

	errors := 0
	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			fmt.Fprintf(os.Stderr, "sear: file not found: %s\n", file)
			errors++
			continue
		}

		outPath := output
		if outPath == "" {
			outPath = file + ".age"
		}

		cmdArgs := []string{}
		for _, r := range recipients {
			cmdArgs = append(cmdArgs, "-r", r)
		}
		for _, rf := range recipientFiles {
			cmdArgs = append(cmdArgs, "-R", rf)
		}
		if armor {
			cmdArgs = append(cmdArgs, "-a")
		}
		cmdArgs = append(cmdArgs, "-o", outPath, "--", file)

		cmd := exec.Command("age", cmdArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		logCmd(cmd)

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "sear: encryption failed: %s\n", file)
			errors++
			continue
		}

		fmt.Printf("OK: %s -> %s\n", file, outPath)
	}

	if errors > 0 {
		os.Exit(1)
	}
}

// ── decrypt ─────────────────────────────────────────────────────────

func cmdDecrypt(args []string) {
	var identities []string
	output := ""
	var files []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			i++
			if i >= len(args) {
				die("-i requires an argument")
			}
			identities = append(identities, expandHome(args[i]))
		case "-o":
			i++
			if i >= len(args) {
				die("-o requires an argument")
			}
			output = expandHome(args[i])
		case "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case "-h", "--help":
			usageDecrypt()
			os.Exit(0)
		default:
			files = append(files, args[i])
		}
	}

	if len(files) == 0 {
		die("no files specified")
	}
	if len(identities) == 0 {
		die("no identity specified (use -i)")
	}
	if output != "" && len(files) > 1 {
		die("-o can only be used with a single file")
	}

	errors := 0
	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			fmt.Fprintf(os.Stderr, "sear: file not found: %s\n", file)
			errors++
			continue
		}

		outPath := output
		if outPath == "" {
			outPath = strings.TrimSuffix(file, ".age")
			if outPath == file {
				outPath = file + ".dec"
			}
		}

		cmdArgs := []string{"-d"}
		for _, id := range identities {
			cmdArgs = append(cmdArgs, "-i", id)
		}
		cmdArgs = append(cmdArgs, "-o", outPath, "--", file)

		cmd := exec.Command("age", cmdArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		logCmd(cmd)

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "sear: decryption failed: %s\n", file)
			errors++
			continue
		}

		fmt.Printf("OK: %s -> %s\n", file, outPath)
	}

	if errors > 0 {
		os.Exit(1)
	}
}

// ── sign ────────────────────────────────────────────────────────────

func cmdSign(args []string) {
	key := ""
	namespace := defaultNamespace
	output := ""
	var files []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-k":
			i++
			if i >= len(args) {
				die("-k requires an argument")
			}
			key = args[i]
		case "-n":
			i++
			if i >= len(args) {
				die("-n requires an argument")
			}
			namespace = args[i]
		case "-o":
			i++
			if i >= len(args) {
				die("-o requires an argument")
			}
			output = expandHome(args[i])
		case "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case "-h", "--help":
			usageSign()
			os.Exit(0)
		default:
			files = append(files, args[i])
		}
	}

	if len(files) == 0 {
		die("no files specified")
	}
	if output != "" && len(files) > 1 {
		die("-o can only be used with a single file")
	}
	if !validNamespace(namespace) {
		die("invalid namespace: must be non-empty with no whitespace")
	}

	if key == "" {
		key = defaultKey
	}
	key = expandHome(key)

	if _, err := os.Stat(key); err != nil {
		die("signing key not found: %s", key)
	}

	errors := 0
	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			fmt.Fprintf(os.Stderr, "sear: file not found: %s\n", file)
			errors++
			continue
		}

		sigDefault := file + ".sig"
		safeRemove(sigDefault)

		cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", key, "-n", namespace, "--", file)
		cmd.Env = cleanEnv(os.Environ())
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		logCmd(cmd)

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "sear: signing failed: %s\n", file)
			errors++
			continue
		}

		sigPath := sigDefault
		if output != "" && output != sigPath {
			if err := moveFile(sigPath, output); err != nil {
				fmt.Fprintf(os.Stderr, "sear: failed to move signature to %s: %v\n", output, err)
				errors++
				continue
			}
			sigPath = output
		}

		fmt.Printf("OK: %s -> %s\n", file, sigPath)
	}

	if errors > 0 {
		os.Exit(1)
	}
}

// ── verify ──────────────────────────────────────────────────────────

func cmdVerify(args []string) {
	pubkey := ""
	namespace := defaultNamespace
	var files []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-p":
			i++
			if i >= len(args) {
				die("-p requires an argument")
			}
			pubkey = args[i]
		case "-n":
			i++
			if i >= len(args) {
				die("-n requires an argument")
			}
			namespace = args[i]
		case "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case "-h", "--help":
			usageVerify()
			os.Exit(0)
		default:
			files = append(files, args[i])
		}
	}

	if len(files) == 0 {
		die("no files specified")
	}
	if !validNamespace(namespace) {
		die("invalid namespace: must be non-empty with no whitespace")
	}

	pubkeys, err := resolvePubkeys(pubkey)
	if err != nil {
		die("%v", err)
	}

	tmp, err := os.CreateTemp("", "sear-signers-*")
	if err != nil {
		die("failed to create temp file: %v", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Remove(tmpPath)
		os.Exit(1)
	}()

	for _, key := range pubkeys {
		fmt.Fprintf(tmp, "sear %s\n", key)
	}
	tmp.Close()

	errors := 0
	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			fmt.Fprintf(os.Stderr, "sear: file not found: %s\n", file)
			errors++
			continue
		}

		sigFile := file + ".sig"
		if _, err := os.Stat(sigFile); err != nil {
			fmt.Fprintf(os.Stderr, "sear: signature not found: %s\n", sigFile)
			errors++
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sear: cannot open %s: %v\n", file, err)
			errors++
			continue
		}

		cmd := exec.Command("ssh-keygen", "-Y", "verify",
			"-f", tmpPath,
			"-I", "sear",
			"-n", namespace,
			"-s", sigFile,
		)
		cmd.Stdin = f
		logCmd(cmd)
		out, err := cmd.CombinedOutput()
		f.Close()

		if err != nil {
			fmt.Fprintf(os.Stderr, "sear: FAIL: %s\n", file)
			if lines := strings.SplitN(string(out), "\n", 2); len(lines) > 0 && lines[0] != "" {
				fmt.Fprintf(os.Stderr, "  %s\n", lines[0])
			}
			errors++
			continue
		}

		fmt.Printf("OK: %s\n", file)
	}

	signal.Stop(sigCh)

	if errors > 0 {
		os.Exit(1)
	}
}

// ── helpers ─────────────────────────────────────────────────────────

// findLatestIdentityFile finds the most recently created age-yubikey-identity file
// in the current directory (where age-plugin-yubikey writes it).
func findLatestIdentityFile() string {
	entries, err := os.ReadDir(".")
	if err != nil {
		return ""
	}
	var newest string
	var newestTime time.Time
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "age-yubikey-identity-") && strings.HasSuffix(e.Name(), ".txt") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if newest == "" || info.ModTime().After(newestTime) {
				newest = e.Name()
				newestTime = info.ModTime()
			}
		}
	}
	return newest
}

// parseRecipientFromIdentity reads an age-yubikey identity file and extracts
// the recipient public key (age1yubikey1q...) from the comment lines.
func parseRecipientFromIdentity(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// The recipient is in a comment line like: "# recipient: age1yubikey1q..."
		if strings.HasPrefix(line, "# recipient:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# recipient:"))
		}
		// Or it might be a bare age1yubikey1 line
		if strings.HasPrefix(line, "age1yubikey1") {
			return line
		}
	}
	return ""
}

func resolvePubkeys(pubkey string) ([]string, error) {
	if pubkey == "" {
		pubkey = expandHome(defaultKey) + ".pub"
	} else if isInlineKey(pubkey) {
		if err := validatePubkeyLine(pubkey); err != nil {
			return nil, err
		}
		return []string{pubkey}, nil
	} else {
		pubkey = expandHome(pubkey)
	}

	info, err := os.Stat(pubkey)
	if err != nil {
		return nil, fmt.Errorf("cannot read public key: %s", pubkey)
	}
	if info.Size() > maxPubkeySize {
		return nil, fmt.Errorf("public key file too large: %s (%d bytes)", pubkey, info.Size())
	}

	data, err := os.ReadFile(pubkey)
	if err != nil {
		return nil, fmt.Errorf("cannot read public key: %s", pubkey)
	}

	var keys []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := validatePubkeyLine(line); err != nil {
			return nil, fmt.Errorf("invalid public key %s: %v", pubkey, err)
		}
		keys = append(keys, line)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in %s", pubkey)
	}

	return keys, nil
}

func validatePubkeyLine(line string) error {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return fmt.Errorf("does not look like an SSH public key")
	}
	if !isInlineKey(fields[0]) {
		return fmt.Errorf("unrecognized key type: %s", fields[0])
	}
	return nil
}

func isInlineKey(s string) bool {
	return strings.HasPrefix(s, "ssh-") ||
		strings.HasPrefix(s, "sk-ssh-") ||
		strings.HasPrefix(s, "sk-ecdsa-") ||
		strings.HasPrefix(s, "ecdsa-")
}

func validNamespace(ns string) bool {
	if ns == "" {
		return false
	}
	for _, r := range ns {
		if unicode.IsSpace(r) || r == 0 {
			return false
		}
	}
	return true
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func safeRemove(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if info.Mode().IsRegular() {
		os.Remove(path)
	}
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}

func cleanEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		strip := false
		for _, name := range dangerousSSHEnvVars {
			if strings.HasPrefix(e, name+"=") {
				strip = true
				break
			}
		}
		if !strip {
			out = append(out, e)
		}
	}
	return out
}

func step(msg string) {
	fmt.Fprintf(os.Stderr, "\n--- %s\n", msg)
}

func logCmd(cmd *exec.Cmd) {
	var parts []string
	for _, arg := range cmd.Args {
		if strings.Contains(arg, " ") || strings.Contains(arg, "\"") {
			parts = append(parts, fmt.Sprintf("%q", arg))
		} else {
			parts = append(parts, arg)
		}
	}
	fmt.Fprintf(os.Stderr, "  $ %s\n", strings.Join(parts, " "))
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sear: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `sear %s — sign, verify, encrypt and decrypt files with SSH keys and age

Usage: sear <command> [flags] FILE...

Signing & Verification:
  sign         Sign files with SSH key (via ssh-agent)
  verify       Verify file signatures
  seal         Encrypt + sign in one step
  unseal       Verify + decrypt in one step

Encryption:
  encrypt      Encrypt files with age
  decrypt      Decrypt files with age

Key Management:
  keygen       Generate ed25519-sk signing key on YubiKey
  age-keygen   Generate age encryption key on YubiKey

Run 'sear <command> -h' for command help.
Run 'sear help setup' for YubiKey getting started guide.
Run 'sear help yubikey' for YubiKey management cheatsheet.
`, version)
}

func helpTopic(topic string) {
	switch topic {
	case "sign":
		usageSign()
	case "verify":
		usageVerify()
	case "seal":
		usageSeal()
	case "unseal":
		usageUnseal()
	case "encrypt":
		usageEncrypt()
	case "decrypt":
		usageDecrypt()
	case "keygen":
		usageKeygen()
	case "age-keygen":
		usageAgeKeygen()
	case "age-identity", "age-list":
		usageYubikey()
	case "setup":
		usageSetup()
	case "yubikey":
		usageYubikey()
	default:
		fmt.Fprintf(os.Stderr, "sear: unknown help topic: %s\n", topic)
		usage()
		os.Exit(1)
	}
}

func usageSign() {
	fmt.Fprintf(os.Stderr, `sear sign — sign files with SSH key via ssh-agent

Usage: sear sign [-k KEY] [-n NS] [-o OUT] FILE...

  -k KEY   Signing key   (default: %s)
  -n NS    Namespace     (default: %s)
  -o OUT   Output path   (default: FILE.sig)

Examples:
  sear sign document.pdf
  sear sign -k ~/.ssh/deploy_sk -n production release.tar.gz
`, defaultKey, defaultNamespace)
}

func usageVerify() {
	fmt.Fprintf(os.Stderr, `sear verify — verify file signatures

Usage: sear verify [-p PUBKEY] [-n NS] FILE...

  -p PUBKEY   Public key or multi-key file   (default: %s.pub)
  -n NS       Namespace                      (default: %s)

  -p accepts a file path, an inline key string, or a file with multiple
  keys (one per line, # comments and blank lines ignored).

Examples:
  sear verify document.pdf
  sear verify -p trusted-keys.pub document.pdf
  sear verify -p "ssh-ed25519 AAAA..." document.pdf
`, defaultKey, defaultNamespace)
}

func usageSeal() {
	fmt.Fprintf(os.Stderr, `sear seal — encrypt + sign in one step

Usage: sear seal -r RCPT [-R FILE] [-a] [-k KEY] [-n NS] FILE...

  -r RCPT   Recipient public key (repeatable)
  -R FILE   Recipients file (repeatable)
  -a        ASCII armor output
  -k KEY    Signing key   (default: %s)
  -n NS     Namespace     (default: %s)

  Encrypts FILE to FILE.age, then signs to FILE.age.sig.

Example (CI/CD):
  sear seal -r age1... secrets.env
`, defaultKey, defaultNamespace)
}

func usageUnseal() {
	fmt.Fprintf(os.Stderr, `sear unseal — verify + decrypt in one step

Usage: sear unseal -i ID [-p PUBKEY] [-n NS] [-o OUT] FILE...

  -i ID       Identity file (repeatable)
  -p PUBKEY   Public key or multi-key file   (default: %s.pub)
  -n NS       Namespace                      (default: %s)
  -o OUT      Decrypted output path

  -p accepts a file path, an inline key string, or a file with multiple
  keys (one per line, # comments and blank lines ignored).

  Verifies FILE.sig first, then decrypts. Fails if signature is invalid.

Example (CI/CD):
  sear unseal -p deploy.pub -i ci-identity.txt secrets.env.age
`, defaultKey, defaultNamespace)
}

func usageEncrypt() {
	fmt.Fprintf(os.Stderr, `sear encrypt — encrypt files with age

Usage: sear encrypt -r RCPT [-R FILE] [-a] [-o OUT] FILE...

  -r RCPT   Recipient public key (repeatable)
  -R FILE   Recipients file (repeatable)
  -a        ASCII armor output
  -o OUT    Output path   (default: FILE.age)

Examples:
  sear encrypt -r age1... secrets.env
  sear encrypt -R ~/.age-recipients secrets.env
`)
}

func usageDecrypt() {
	fmt.Fprintf(os.Stderr, `sear decrypt — decrypt files with age

Usage: sear decrypt -i ID [-o OUT] FILE...

  -i ID    Identity file (repeatable)
  -o OUT   Output path   (default: strip .age or add .dec)

Example:
  sear decrypt -i age-yubikey-identity.txt secrets.env.age
`)
}

func usageKeygen() {
	fmt.Fprintf(os.Stderr, `sear keygen — generate ed25519-sk signing key on YubiKey

Usage: sear keygen -C NAME [-f PATH]

  -C NAME   Key name (required) — used as both the SSH comment and
            the FIDO2 application ID (ssh:NAME) on the YubiKey
  -f PATH   Key file path   (default: %s)

  Generates a resident, verify-required ed25519-sk key. Requires
  YubiKey PIN and touch. Fails if the key file already exists.

  The -C name lets you match key files on disk to credentials on the
  YubiKey (visible via 'ykman fido credentials list').

Examples:
  sear keygen -C nxmini0
  sear keygen -C ops@acme.com -f ~/.ssh/deploy_sk
`, defaultKey)
}

func usageAgeKeygen() {
	fmt.Fprintf(os.Stderr, `sear age-keygen — generate age encryption key on YubiKey

Usage: sear age-keygen [-s SLOT] [-o FILE]

  -s SLOT   YubiKey PIV slot   (default: %s)
  -o FILE   Save identity file to this path

  Creates a key with pin-policy=always and touch-policy=always.
  Prints the age recipient (age1yubikey1q...) to stdout.

Example:
  sear age-keygen -o ~/keys/age-identity.txt
`, defaultAgeSlot)
}

func usageSetup() {
	fmt.Fprintf(os.Stderr, `GETTING STARTED

  1. Install dependencies:
     macOS:   brew install age age-plugin-yubikey ykman libfido2
     FreeBSD: pkg install age age-plugin-yubikey yubikey-manager libfido2
     Linux:   apt install age yubikey-manager libfido2-tools

  2. Prepare YubiKey PIV (first time only):
     ykman piv access change-management-key -a TDES --protect
     ykman piv access change-pin
     # Do this BEFORE age-keygen or you'll get a management key error.

  3. Create SSH signing key:     sear keygen -C you@email.com
  4. Create age encryption key:  sear age-keygen -o age-identity.txt
  5. Sign a file:                sear sign document.pdf
  6. Verify a file:              sear verify document.pdf
  7. Encrypt a file:             sear encrypt -r age1... secrets.env
  8. Decrypt a file:             sear decrypt -i age-identity.txt secrets.env.age

NEW MACHINE SETUP
  ssh-keygen -K                    Pull resident keys from YubiKey
  ssh-add ~/.ssh/id_ed25519_sk     Add to SSH agent
  ssh-add -L                       Verify loaded keys

GIT COMMIT SIGNING
  git config --global gpg.format ssh
  git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
  git config --global commit.gpgsign true

LOST YOUR IDENTITY FILE?
  age-plugin-yubikey --identity --slot 1 > age-yubikey-identity.txt

NOTES
  SSH signing uses FIDO2 (touch only after first setup).
  Age encryption uses PIV (PIN + touch every time).

DEPENDENCIES
  Required: ssh-keygen, age
  Optional: age-plugin-yubikey, ykman, libfido2
`)
}

func usageYubikey() {
	fmt.Fprintf(os.Stderr, `YUBIKEY MANAGEMENT

SSH (FIDO2) keys:
  ykman fido credentials list                List SSH keys on YubiKey
  ykman fido credentials delete ssh:NAME     Delete SSH key by app ID

Age (PIV) keys:
  age-plugin-yubikey --list                  List age keys on YubiKey
  age-plugin-yubikey --identity \
    --serial SERIAL --slot SLOT              Recreate age identity file

  Lost your identity file?
    age-plugin-yubikey --identity --slot 1 > age-yubikey-identity.txt

Device:
  ykman list                                 List connected YubiKeys
  ykman info                                 Device info
  ykman piv info                             PIV slot info
  ykman piv access change-pin                Change PIV PIN
  ykman piv access unblock-pin               Unblock PIN with PUK
`)
}
