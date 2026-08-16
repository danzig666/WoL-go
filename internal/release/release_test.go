package release

import (
	"strings"
	"testing"
)

// A checksum list signed by the real release key, so this test fails if the
// public key in release.go is ever replaced or corrupted. The signature is not
// a secret: it proves only that the holder of the private key signed these two
// lines.
const (
	testSums = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  hello.bin\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.bin\n"
	testSig = "qWxNFJ+h0yy+E8+7dx4TJhpa0Se3lL0APdCTqjc+txZXCUrTkm+0CfIwQDw5McYnpiLp5JnRopy2YBqvA1E9CQ=="
)

func TestVerifyAcceptsARealSignature(t *testing.T) {
	sums, err := Verify([]byte(testSums), []byte(testSig))
	if err != nil {
		t.Fatalf("the embedded public key rejected a genuine signature: %v", err)
	}
	if !sums.Has("hello.bin") || !sums.Has("empty.bin") {
		t.Fatalf("checksums missing entries: %v", sums)
	}
	if err := sums.Check("hello.bin", strings.NewReader("hello\n")); err != nil {
		t.Errorf("matching content rejected: %v", err)
	}
	if err := sums.Check("hello.bin", strings.NewReader("hello!\n")); err == nil {
		t.Error("altered content accepted")
	}
	if err := sums.Check("absent.bin", strings.NewReader("")); err == nil {
		t.Error("a file outside the release was accepted")
	}
}

// The important negative: a checksum list that was tampered with must not
// verify, however plausible it looks. This is the case that stops a
// compromised mirror from serving its own binary.
func TestVerifyRejectsTampering(t *testing.T) {
	altered := strings.Replace(testSums, "5891", "5892", 1)
	if _, err := Verify([]byte(altered), []byte(testSig)); err == nil {
		t.Fatal("an altered checksum list verified")
	}

	for name, sig := range map[string]string{
		"empty":        "",
		"not base64":   "!!!!",
		"wrong length": "AAAA",
		"other key": "0000000000000000000000000000000000000000000000000000000000000000" +
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000==",
	} {
		if _, err := Verify([]byte(testSums), []byte(sig)); err == nil {
			t.Errorf("%s signature accepted", name)
		}
	}
}

func TestParseChecksumsRejectsRubbish(t *testing.T) {
	for _, in := range []string{
		"",
		"\n\n",
		"nothexhere  file.bin",
		"5891b5b5  file.bin", // too short to be a sha256
		"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
	} {
		if _, err := parseChecksums([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestParseChecksumsAcceptsBinaryMarker(t *testing.T) {
	// sha256sum writes "*name" for files it read in binary mode.
	sums, err := parseChecksums([]byte("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03 *hello.bin\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !sums.Has("hello.bin") {
		t.Fatalf("got %v", sums)
	}
}

func TestCompare(t *testing.T) {
	older := []struct{ a, b string }{
		{"v1.0.0", "v1.0.1"},
		{"v1.0.0", "v1.1.0"},
		{"v1.9.0", "v2.0.0"},
		{"1.0.0", "v1.0.1"},      // the v is optional
		{"v1.1", "v1.1.1"},       // missing parts count as zero
		{"v1.2.0-rc1", "v1.2.0"}, // a pre-release precedes its release
		{"v1.2.0-rc1", "v1.2.0-rc2"},
		{"dev", "v0.0.1"},     // an unstamped build is always behind
		{"rubbish", "v1.0.0"}, // and so is anything unparseable
	}
	for _, c := range older {
		if Compare(c.a, c.b) != -1 {
			t.Errorf("Compare(%q, %q) should be -1", c.a, c.b)
		}
		if Compare(c.b, c.a) != 1 {
			t.Errorf("Compare(%q, %q) should be 1", c.b, c.a)
		}
		if !IsNewer(c.b, c.a) {
			t.Errorf("%q should be newer than %q", c.b, c.a)
		}
		if IsNewer(c.a, c.b) {
			t.Errorf("%q should not be newer than %q", c.a, c.b)
		}
	}

	same := []struct{ a, b string }{
		{"v1.2.3", "1.2.3"},
		{"v1.2.0", "v1.2.0"},
		{"v1.2.0", "v1.2.0+build7"},
		{"dev", "dev"},
		{"", "dev"},
	}
	for _, c := range same {
		if Compare(c.a, c.b) != 0 {
			t.Errorf("Compare(%q, %q) should be 0", c.a, c.b)
		}
	}

	if Valid("dev") || Valid("") || Valid("nonsense") {
		t.Error("Valid accepted a non-version")
	}
	if !Valid("v1.0.0") || !Valid("1.0") {
		t.Error("Valid rejected a version")
	}
}
