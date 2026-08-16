// Package release holds what both the server and the agent need to know about
// a published release: how to tell one version from another, and how to decide
// whether a downloaded file is genuine.
//
// Genuineness matters more here than anywhere else in the program. An update
// mechanism is, by construction, a way to make another machine run code it has
// never seen, and the agent's whole security argument until now was that it
// understood only three commands and could therefore never become a shell.
// What preserves that argument is this: the agent runs a new binary only if it
// was signed by the release key, whoever handed it over. The server is a
// convenience — it saves every agent machine from needing internet access —
// but it is not trusted. A compromised server can serve an old signed build,
// which is a nuisance; it cannot serve a hostile one.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// PublicKey is the public half of the release signing key, in base64. Its
// private half lives only in the repository's GitHub Actions secrets and signs
// SHA256SUMS.txt during the release build.
//
// Changing this constant breaks updates for every agent already installed,
// because they verify with the copy compiled into them. Treat it as permanent.
const PublicKey = "hhY8gG80JUQ+loTCBHaTm/FQuO03O7f86V57vQVJdOk="

// ChecksumFile and SignatureFile are the release assets carrying the checksums
// of every other asset, and the signature over that list.
const (
	ChecksumFile  = "SHA256SUMS.txt"
	SignatureFile = "SHA256SUMS.txt.sig"
)

var errNotSigned = errors.New("the checksum list is not signed by the release key")

func publicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(PublicKey)
	if err != nil {
		return nil, fmt.Errorf("the built-in release key is unreadable: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the built-in release key is %d bytes, expected %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// parseSignature accepts the signature either as raw bytes or base64 text,
// since which one a tool writes is a coin toss and both are unambiguous at
// this length.
func parseSignature(sig []byte) ([]byte, error) {
	if len(sig) == ed25519.SignatureSize {
		return sig, nil
	}
	text := strings.TrimSpace(string(sig))
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("the signature is neither %d raw bytes nor base64: %w", ed25519.SignatureSize, err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("the signature decodes to %d bytes, expected %d", len(raw), ed25519.SignatureSize)
	}
	return raw, nil
}

// Checksums maps a release asset's file name to its expected SHA-256, and is
// only ever produced by Verify, so holding one means the list was signed.
type Checksums map[string]string

// Verify checks that sig is a signature over sums by the release key, and
// returns the checksums it lists. Everything downstream depends on this being
// the only way to obtain a Checksums value.
func Verify(sums, sig []byte) (Checksums, error) {
	key, err := publicKey()
	if err != nil {
		return nil, err
	}
	signature, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, sums, signature) {
		return nil, errNotSigned
	}
	return parseChecksums(sums)
}

// parseChecksums reads the output of sha256sum: a hex digest, whitespace, an
// optional binary marker, then the file name.
func parseChecksums(sums []byte) (Checksums, error) {
	out := Checksums{}
	for _, line := range strings.Split(string(sums), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		digest, name, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("unreadable checksum line %q", line)
		}
		if _, err := hex.DecodeString(digest); err != nil || len(digest) != sha256.Size*2 {
			return nil, fmt.Errorf("unreadable checksum in line %q", line)
		}
		name = strings.TrimLeft(name, " *")
		if name == "" {
			return nil, fmt.Errorf("checksum line %q names no file", line)
		}
		out[name] = strings.ToLower(digest)
	}
	if len(out) == 0 {
		return nil, errors.New("the checksum list is empty")
	}
	return out, nil
}

// Check reads r to the end and reports whether it is the named release asset.
func (c Checksums) Check(name string, r io.Reader) error {
	want, ok := c[name]
	if !ok {
		return fmt.Errorf("%s is not part of this release", name)
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%s does not match the signed checksum", name)
	}
	return nil
}

// Has reports whether the release includes the named asset.
func (c Checksums) Has(name string) bool {
	_, ok := c[name]
	return ok
}

// Version comparison.
//
// Versions look like v1.2.3, optionally with a pre-release suffix such as
// v1.2.3-rc1. An unstamped development build calls itself "dev" and is treated
// as older than every real release, so a developer running one is offered the
// update rather than told they are ahead.

// DevVersion is what a binary reports when it was built without a version
// stamp, which is what happens on a plain "go build".
const DevVersion = "dev"

type parsedVersion struct {
	nums []int
	pre  string
	ok   bool
}

func parseVersion(v string) parsedVersion {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" || v == DevVersion {
		return parsedVersion{}
	}
	core, pre, _ := strings.Cut(v, "-")
	if i := strings.IndexAny(core, "+ "); i >= 0 {
		core = core[:i]
	}
	p := parsedVersion{pre: pre, ok: true}
	for _, part := range strings.Split(core, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return parsedVersion{}
		}
		p.nums = append(p.nums, n)
	}
	if len(p.nums) == 0 {
		return parsedVersion{}
	}
	return p
}

// Compare orders two versions: -1 if a is older, 1 if a is newer, 0 if they
// are equivalent. Anything unparseable sorts as oldest, which keeps a
// malformed tag from ever looking like an upgrade.
func Compare(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	switch {
	case !pa.ok && !pb.ok:
		return 0
	case !pa.ok:
		return -1
	case !pb.ok:
		return 1
	}
	for i := 0; i < len(pa.nums) || i < len(pb.nums); i++ {
		x, y := 0, 0
		if i < len(pa.nums) {
			x = pa.nums[i]
		}
		if i < len(pb.nums) {
			y = pb.nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	// A pre-release comes before the release it leads up to: 1.2.0-rc1 < 1.2.0.
	switch {
	case pa.pre == pb.pre:
		return 0
	case pa.pre == "":
		return 1
	case pb.pre == "":
		return -1
	case pa.pre < pb.pre:
		return -1
	default:
		return 1
	}
}

// IsNewer reports whether candidate is a later version than current.
func IsNewer(candidate, current string) bool {
	return Compare(candidate, current) > 0
}

// Valid reports whether a version string is one we can reason about.
func Valid(v string) bool { return parseVersion(v).ok }

// AgentAsset names the agent binary for a Windows architecture, matching what
// the release workflow builds.
func AgentAsset(goarch string) string {
	return "wol-agent-windows-" + goarch + ".exe"
}
