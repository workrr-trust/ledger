// idcheck — classify every certificate Sigstore's Fulcio issued under workrr's
// signer identity, as found by rekor-monitor's ct_monitor in the CT log.
//
// A certificate is EXPECTED only if its SAN is one of workrr's signing workflows
//
//	https://github.com/workrr-trust/certify/.github/workflows/certify.yml@refs/tags/<tag>
//	https://github.com/workrr-trust/certify/.github/workflows/scan.yml@refs/tags/<tag>   (public scans)
//
// for a released tag, AND its Build Signer Digest (OID 1.3.6.1.4.1.57264.1.10) is
// that tag's SHA. For an annotated tag GitHub records the tag OBJECT's SHA (not the
// commit it points to), so both are accepted. Anything else — a branch ref, an unknown tag, a
// mismatched commit — is UNEXPECTED: possible forge compromise or a forged certificate.
//
//	idcheck -scan 414771731:414778236 -tags tags.txt -out identities/2026-10.jsonl
//	idcheck -cert leaf.der -tags tags.txt   # classify one cert (testing)
//
// -scan reads EVERY CT entry in [start, end). rekor-monitor's ct_monitor verifies the
// log's signed tree head and consistency and keeps the cursor, but its identity search
// makes a single get-entries call, and the log returns at most a few hundred entries
// per call, so it silently skips the rest of the window. idcheck does the search
// itself, looping until each index is read, and fails if any entry can't be read.
//
// tags.txt has "<tag> <sha> [<sha>…]" per line: the tag object SHA and/or the commit it
// points to. Exit status 2 means at least one UNEXPECTED certificate was found.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
)

// The workflows that sign workrr certificates: certify.yml (called from a maintainer's
// repo) and scan.yml (public scans run in workrr-trust/certify).
var signerWorkflows = []string{"certify.yml", "scan.yml"}

const workflowBase = "github.com/workrr-trust/certify/.github/workflows/"

var (
	oidBuildSignerDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 10}
	oidSourceRepoURI     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidRunInvocationURI  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}
	oidIssuerV2          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	tagRef               = regexp.MustCompile(`^refs/tags/(v\d+\.\d+\.\d+)$`)
)

type record struct {
	CTIndex      int64  `json:"ct_index,omitempty"`
	LoggedAt     string `json:"logged_at,omitempty"`
	SAN          string `json:"san"`
	Issuer       string `json:"issuer,omitempty"`
	SignerDigest string `json:"signer_digest,omitempty"`
	SourceRepo   string `json:"source_repo,omitempty"`
	Run          string `json:"run,omitempty"`
	Expected     bool   `json:"expected"`
	Reason       string `json:"reason"`
}

func main() {
	scanRange := flag.String("scan", "", "scan CT entries START:END (END exclusive)")
	certPath := flag.String("cert", "", "classify a single DER or PEM certificate (testing)")
	tagsPath := flag.String("tags", "", `file with "<tag> <sha> [<sha>…]" lines for released certifier tags`)
	ctURL := flag.String("ct", "https://ctfe.sigstore.dev/2022", "CT log base URL")
	outPath := flag.String("out", "", "append one JSON line per certificate to this file")
	flag.Parse()

	tags, err := readTags(*tagsPath)
	check(err)

	var recs []record
	switch {
	case *certPath != "":
		raw, err := os.ReadFile(*certPath)
		check(err)
		cert, err := parseCert(raw)
		check(err)
		recs = append(recs, classify(cert, tags))
	case *scanRange != "":
		from, to, err := parseRange(*scanRange)
		check(err)
		hits, err := scan(*ctURL, from, to)
		check(err)
		fmt.Printf("idcheck: scanned CT entries %d..%d (%d)\n", from, to-1, to-from)
		for _, h := range hits {
			if h.cert == nil {
				recs = append(recs, record{CTIndex: h.index, Reason: "entry mentions the certifier but could not be parsed"})
				continue
			}
			r := classify(h.cert, tags)
			r.CTIndex, r.LoggedAt = h.index, h.ts
			recs = append(recs, r)
		}
	default:
		check(errors.New("need -scan or -cert"))
	}

	unexpected := 0
	var out io.Writer = io.Discard
	if *outPath != "" && len(recs) > 0 {
		fh, err := os.OpenFile(*outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		check(err)
		defer fh.Close()
		out = fh
	}
	for _, r := range recs {
		line, _ := json.Marshal(r)
		fmt.Fprintln(out, string(line))
		fmt.Println(string(line))
		if !r.Expected {
			unexpected++
		}
	}
	fmt.Printf("idcheck: %d certificate(s), %d unexpected\n", len(recs), unexpected)
	if unexpected > 0 {
		os.Exit(2)
	}
}

func classify(c *x509.Certificate, tags map[string][]string) record {
	r := record{
		Issuer:       ext(c, oidIssuerV2),
		SignerDigest: ext(c, oidBuildSignerDigest),
		SourceRepo:   ext(c, oidSourceRepoURI),
		Run:          ext(c, oidRunInvocationURI),
	}
	for _, u := range c.URIs {
		r.SAN = u.String()
	}
	prefix := ""
	for _, w := range signerWorkflows {
		if p := "https://" + workflowBase + w + "@"; strings.HasPrefix(r.SAN, p) {
			prefix = p
		}
	}
	switch {
	case prefix == "":
		r.Reason = "SAN is not a workrr certifier workflow"
	case r.Issuer != "" && r.Issuer != "https://token.actions.githubusercontent.com":
		r.Reason = "issuer is not GitHub Actions"
	default:
		ref := strings.TrimPrefix(r.SAN, prefix)
		m := tagRef.FindStringSubmatch(ref)
		switch {
		case m == nil:
			r.Reason = "signed from " + ref + ", not a release tag"
		case len(tags[m[1]]) == 0:
			r.Reason = "tag " + m[1] + " is not a released certifier tag"
		case !contains(tags[m[1]], r.SignerDigest):
			r.Reason = fmt.Sprintf("certifier SHA %s does not match tag %s (%s)", r.SignerDigest, m[1], strings.Join(tags[m[1]], ", "))
		default:
			r.Expected, r.Reason = true, "released tag "+m[1]+" at its tag SHA"
		}
	}
	return r
}

// Fulcio v2 extensions are DER-encoded UTF8Strings; the v1 issuer is raw bytes.
func ext(c *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			var s string
			if rest, err := asn1.Unmarshal(e.Value, &s); err == nil && len(rest) == 0 {
				return s
			}
			return string(e.Value)
		}
	}
	return ""
}

// Bytes every certificate issued to a certifier workflow contains (in its SAN).
var needles = func() [][]byte {
	var out [][]byte
	for _, w := range signerWorkflows {
		out = append(out, []byte(workflowBase+w+"@"))
	}
	return out
}()

func hasNeedle(b ...[]byte) bool {
	for _, x := range b {
		for _, n := range needles {
			if bytes.Contains(x, n) {
				return true
			}
		}
	}
	return false
}

type hit struct {
	index int64
	ts    string
	cert  *x509.Certificate
}

func parseRange(s string) (int64, int64, error) {
	a, b, ok := strings.Cut(s, ":")
	from, err1 := strconv.ParseInt(a, 10, 64)
	to, err2 := strconv.ParseInt(b, 10, 64)
	if !ok || err1 != nil || err2 != nil || from < 0 || to < from {
		return 0, 0, fmt.Errorf("bad -scan range %q", s)
	}
	return from, to, nil
}

// scan reads every entry in [from, to) and returns those that mention the certifier
// workflow. The log may return fewer entries than asked for, so each worker keeps
// asking from where the last response stopped.
func scan(base string, from, to int64) ([]hit, error) {
	const chunk, workers = 4096, 8
	client := &http.Client{Timeout: 60 * time.Second}
	var (
		mu    sync.Mutex
		hits  []hit
		first error
		wg    sync.WaitGroup
		jobs  = make(chan [2]int64)
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				for i := j[0]; i < j[1]; {
					entries, err := getEntries(client, base, i, j[1]-1)
					if err != nil {
						mu.Lock()
						if first == nil {
							first = err
						}
						mu.Unlock()
						break
					}
					for k := range entries {
						idx := i + int64(k)
						e := &entries[k]
						if !hasNeedle(e.LeafInput, e.ExtraData) {
							continue
						}
						h, err := parseLeaf(idx, e)
						mu.Lock()
						if err != nil {
							// A matching entry we can't parse is reported, never skipped.
							hits = append(hits, hit{index: idx})
							fmt.Fprintf(os.Stderr, "idcheck: entry %d mentions the certifier but did not parse: %v\n", idx, err)
						} else {
							hits = append(hits, h)
						}
						mu.Unlock()
					}
					i += int64(len(entries))
				}
			}
		}()
	}
	for i := from; i < to; i += chunk {
		jobs <- [2]int64{i, min(i+chunk, to)}
	}
	close(jobs)
	wg.Wait()
	return hits, first
}

func getEntries(client *http.Client, base string, start, end int64) ([]ct.LeafEntry, error) {
	url := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", strings.TrimRight(base, "/"), start, end)
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		var body ct.GetEntriesResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		switch {
		case resp.StatusCode != 200:
			lastErr = fmt.Errorf("get-entries %d-%d: HTTP %d", start, end, resp.StatusCode)
		case err != nil:
			lastErr = err
		case len(body.Entries) == 0:
			lastErr = fmt.Errorf("get-entries %d-%d: no entries", start, end)
		default:
			return body.Entries, nil
		}
	}
	return nil, lastErr
}

func parseLeaf(idx int64, e *ct.LeafEntry) (hit, error) {
	entry, err := ct.LogEntryFromLeaf(idx, e)
	if entry == nil {
		return hit{}, err
	}
	ts := time.UnixMilli(int64(entry.Leaf.TimestampedEntry.Timestamp)).UTC().Format(time.RFC3339)
	switch {
	case entry.Precert != nil && entry.Precert.TBSCertificate != nil:
		return hit{idx, ts, entry.Precert.TBSCertificate}, nil
	case entry.X509Cert != nil:
		return hit{idx, ts, entry.X509Cert}, nil
	}
	return hit{}, fmt.Errorf("no certificate (%v)", err)
}

func parseCert(raw []byte) (*x509.Certificate, error) {
	s := string(raw)
	if strings.Contains(s, "-----BEGIN") {
		var b strings.Builder
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(l, "-----") {
				b.WriteString(strings.TrimSpace(l))
			}
		}
		der, err := base64.StdEncoding.DecodeString(b.String())
		if err != nil {
			return nil, err
		}
		raw = der
	}
	c, err := x509.ParseCertificate(raw)
	if c == nil {
		return nil, err
	}
	return c, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func readTags(path string) (map[string][]string, error) {
	tags := map[string][]string{}
	if path == "" {
		return tags, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			tags[f[0]] = append(tags[f[0]], f[1:]...)
		}
	}
	return tags, nil
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "idcheck:", err)
		os.Exit(1)
	}
}
