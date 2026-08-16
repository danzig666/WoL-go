// Signs a file with the release key, for the release workflow.
//
// The key comes from the environment rather than the command line so it does
// not appear in a process list or a build log. In CI that environment variable
// is a repository secret; nobody needs to run this by hand.
//
//	WOLGO_SIGNING_KEY=<base64> go run ./tools/sign dist/SHA256SUMS.txt
//
// It writes <file>.sig next to the input, containing the base64 signature, and
// checks the result against the public key compiled into the program so a
// mismatched key pair fails here rather than on every user's machine.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"WoL-go/internal/release"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: WOLGO_SIGNING_KEY=<base64> sign <file>")
		os.Exit(2)
	}
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		os.Exit(1)
	}

	secret := os.Getenv("WOLGO_SIGNING_KEY")
	if secret == "" {
		fail("WOLGO_SIGNING_KEY is not set")
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		fail("WOLGO_SIGNING_KEY is not valid base64: %v", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		fail("WOLGO_SIGNING_KEY is %d bytes, expected %d", len(raw), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(raw)

	body, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("%v", err)
	}
	sig := ed25519.Sign(priv, body)

	// Verify with the public half the binaries carry. If these have drifted
	// apart, every download would fail verification on the far side; better to
	// break the release build.
	if _, err := release.Verify(body, sig); err != nil {
		fail("the signing key does not match the public key in internal/release: %v", err)
	}

	out := os.Args[1] + ".sig"
	if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		fail("%v", err)
	}
	fmt.Println("signed", out)
}
