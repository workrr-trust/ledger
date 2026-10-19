// ckpt — verify Rekor v1 checkpoints committed to the Workrr Trust ledger.
//
// Every checkpoint signature is checked against the Rekor public key from the
// Sigstore trusted root (fetched and verified via TUF, or pinned with
// --trusted-root). Consistency proofs are fetched from Rekor but verified
// locally, so a dishonest or compromised log server cannot pass them.
//
//	ckpt consistent [--trusted-root f] <old> <new>   one checkpoint each (file)
//	ckpt chain      [--trusted-root f] <file>...      every consecutive pair
//	ckpt show       <file>                            print origin, size, root
//
// Files hold one checkpoint per line in rekor-monitor's format (the signed note
// with newlines escaped as \n), optionally prefixed by an RFC 3339 time and a
// space, as in checkpoints/*/history/*.txt. Blank lines and # comments are skipped.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

type checkpoint struct {
	Origin string // e.g. "rekor.sigstore.dev - 1193050959916656506"
	Host   string
	TreeID string
	Size   uint64
	Root   []byte
	note   string
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	trustedRoot := fs.String("trusted-root", "", "pinned Sigstore trusted_root.json (default: fetch via TUF)")
	fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "show":
		err = show(fs.Args())
	case "consistent":
		if fs.NArg() != 2 {
			usage()
		}
		err = runChain(*trustedRoot, fs.Args())
	case "chain":
		if fs.NArg() < 1 {
			usage()
		}
		err = runChain(*trustedRoot, fs.Args())
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ckpt:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ckpt consistent|chain [--trusted-root f] <file>...  |  ckpt show <file>")
	os.Exit(2)
}

func show(files []string) error {
	cps, err := readFiles(files)
	if err != nil {
		return err
	}
	for _, c := range cps {
		fmt.Printf("%s\t%d\t%s\n", c.Origin, c.Size, hex.EncodeToString(c.Root))
	}
	return nil
}

func runChain(trustedRootPath string, files []string) error {
	cps, err := readFiles(files)
	if err != nil {
		return err
	}
	if len(cps) == 0 {
		return errors.New("no checkpoints")
	}
	keys, err := rekorKeys(trustedRootPath)
	if err != nil {
		return err
	}
	for _, c := range cps {
		if err := verifySignature(c, keys); err != nil {
			return fmt.Errorf("checkpoint %s size %d: %w", c.Origin, c.Size, err)
		}
	}
	for i := 1; i < len(cps); i++ {
		a, b := cps[i-1], cps[i]
		if err := consistent(a, b); err != nil {
			return fmt.Errorf("size %d → %d: %w", a.Size, b.Size, err)
		}
		fmt.Printf("✓ consistent %s %d → %d\n", b.Origin, a.Size, b.Size)
	}
	fmt.Printf("OK: %d checkpoint(s), signatures valid, chain append-only\n", len(cps))
	return nil
}

func readFiles(files []string) ([]checkpoint, error) {
	var out []checkpoint
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if t, rest, ok := strings.Cut(line, " "); ok {
				if _, err := time.Parse(time.RFC3339, t); err == nil {
					line = rest
				}
			}
			c, err := parse(strings.ReplaceAll(line, `\n`, "\n"))
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", f, n, err)
			}
			out = append(out, c)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parse reads a C2SP signed note whose body is a tlog checkpoint.
func parse(note string) (checkpoint, error) {
	body, _, ok := strings.Cut(note, "\n\n")
	if !ok {
		return checkpoint{}, errors.New("not a signed note")
	}
	lines := strings.Split(body, "\n")
	if len(lines) < 3 {
		return checkpoint{}, errors.New("checkpoint body too short")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return checkpoint{}, fmt.Errorf("bad size: %w", err)
	}
	rootHash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(rootHash) != sha256.Size {
		return checkpoint{}, errors.New("bad root hash")
	}
	host, treeID, ok := strings.Cut(lines[0], " - ")
	if !ok {
		return checkpoint{}, fmt.Errorf("origin %q is not a Rekor v1 origin", lines[0])
	}
	return checkpoint{Origin: lines[0], Host: host, TreeID: treeID, Size: size, Root: rootHash, note: note}, nil
}

type logKey struct {
	host string
	key  *ecdsa.PublicKey
}

func rekorKeys(trustedRootPath string) ([]logKey, error) {
	var tr *root.TrustedRoot
	var err error
	if trustedRootPath != "" {
		tr, err = root.NewTrustedRootFromPath(trustedRootPath)
	} else {
		tr, err = root.FetchTrustedRoot()
	}
	if err != nil {
		return nil, fmt.Errorf("trusted root: %w", err)
	}
	var keys []logKey
	for _, tl := range tr.RekorLogs() {
		k, ok := tl.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			continue // v2 (ed25519) logs use a different origin format
		}
		u, err := url.Parse(tl.BaseURL)
		if err != nil {
			continue
		}
		keys = append(keys, logKey{host: u.Host, key: k})
	}
	return keys, nil
}

// verifySignature checks a "— <host> <base64(keyhint‖sig)>" line against the
// trusted-root key for that host. Rekor v1 signs the note body with ECDSA P-256.
func verifySignature(c checkpoint, keys []logKey) error {
	body, sigs, _ := strings.Cut(c.note, "\n\n")
	msg := sha256.Sum256([]byte(body + "\n"))
	for _, line := range strings.Split(strings.TrimRight(sigs, "\n"), "\n") {
		name, b64, ok := strings.Cut(strings.TrimPrefix(line, "— "), " ")
		if !ok || name != c.Host {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) < 5 {
			continue
		}
		for _, k := range keys {
			if k.host == c.Host && ecdsa.VerifyASN1(k.key, msg[:], raw[4:]) {
				return nil
			}
		}
	}
	return errors.New("no valid signature from a trusted Rekor key")
}

func consistent(a, b checkpoint) error {
	if a.Origin != b.Origin {
		return fmt.Errorf("different logs (%s vs %s): start a new chain per shard", a.Origin, b.Origin)
	}
	if a.Size > b.Size {
		a, b = b, a
	}
	if a.Size == b.Size {
		if !bytes.Equal(a.Root, b.Root) {
			return errors.New("SPLIT VIEW: same tree size, different root hashes")
		}
		return nil
	}
	hashes, err := fetchProof(a, b)
	if err != nil {
		return err
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, a.Size, b.Size, hashes, a.Root, b.Root); err != nil {
		return fmt.Errorf("INCONSISTENT: %w", err)
	}
	return nil
}

func fetchProof(a, b checkpoint) ([][]byte, error) {
	q := url.Values{"firstSize": {strconv.FormatUint(a.Size, 10)}, "lastSize": {strconv.FormatUint(b.Size, 10)}, "treeID": {a.TreeID}}
	u := "https://" + a.Host + "/api/v1/log/proof?" + q.Encode()
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
		}
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "workrr-trust-ledger-ckpt")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		var body struct {
			Hashes []string `json:"hashes"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != 200 || err != nil {
			lastErr = fmt.Errorf("GET %s: HTTP %d %v", u, resp.StatusCode, err)
			continue
		}
		out := make([][]byte, len(body.Hashes))
		for i, h := range body.Hashes {
			if out[i], err = hex.DecodeString(h); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, lastErr
}
