#!/usr/bin/env bash
# Audit the whole ledger from a clone. Trusts nothing in this repo except the
# files' cryptography: keys come from the Sigstore trusted root via TUF.
#
#   bash scripts/audit.sh            # checkpoints + certificates
#   MIRRORS="https://gitlab.com/workrr-trust/ledger.git https://codeberg.org/workrr-trust/ledger.git" bash scripts/audit.sh
#
# Needs: go, git, jq. Builds tools/ckpt and the workrr CLI (pinned release).
set -euo pipefail
cd "$(dirname "$0")/.."

# workrr-trust/certify v0.1.0 (the certifier release whose identity the trust policy accepts)
certify_ref=${CERTIFY_REF:-edf382958dd7ce070db0ed13af1cc8c31a150901}
bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
echo "== building ckpt and workrr @${certify_ref:0:12}"
(cd tools/ckpt && CGO_ENABLED=0 go build -o "$bin/ckpt" .)
GOBIN=$bin go install "github.com/workrr-trust/certify/go/cmd/workrr@$certify_ref"
export PATH="$bin:$PATH"

echo "== 1. checkpoint chain: every committed checkpoint signed by Rekor, each consistent with the next"
ckpt chain checkpoints/rekor.sigstore.dev/history/*.txt
latest_hist=$(ckpt show checkpoints/rekor.sigstore.dev/history/*.txt | tail -1)
[ "$(ckpt show checkpoints/rekor.sigstore.dev/latest.txt)" = "$latest_hist" ] || { echo "latest.txt is not the last history entry"; exit 1; }
echo "   and the live log is consistent with our latest:"
curl -fsS https://rekor.sigstore.dev/api/v1/log | jq -r '.signedTreeHead | gsub("\n"; "\\n")' >"$bin/live.txt"
ckpt consistent checkpoints/rekor.sigstore.dev/latest.txt "$bin/live.txt"

echo "== 2. certificates: re-verify each against its source and the witnessed log"
fails=0 count=0
for f in certificates/sha256/*/*.sigstore.json; do
  [ -e "$f" ] || continue
  count=$((count + 1))
  digest=$(basename "$(dirname "$f")")
  statement=$(jq -r .dsseEnvelope.payload "$f" | base64 -d)
  uri=$(jq -r .predicate.source.uri <<<"$statement")
  commit=$(jq -r .predicate.source.commit <<<"$statement")
  path=$(jq -r .predicate.source.path <<<"$statement")
  src="$bin/src-$commit"
  if [ ! -d "$src" ]; then
    git init --quiet "$src"
    git -C "$src" fetch --quiet --depth 1 "$uri" "$commit" && git -C "$src" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
  fi
  jq -r '.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope | gsub("\n"; "\\n")' "$f" >"$bin/c.txt"
  workrr verify "$src/$path" --bundle "$f" --json >"$bin/v.json" || true
  level=$(jq -r 'select(.ok == true and .artifactDigest == "'"$digest"'") | .level' "$bin/v.json")
  if [ -n "$level" ] && ckpt consistent "$bin/c.txt" checkpoints/rekor.sigstore.dev/latest.txt >/dev/null; then
    echo "   ✓ $f ($level, $uri@${commit:0:12} $path)"
  else
    echo "   ✗ $f: $(jq -c '[.bundles[]?.error // empty]' "$bin/v.json" 2>/dev/null)"
    fails=$((fails + 1))
  fi
done
echo "   $count certificate(s), $fails failure(s)"

DEFAULT_MIRRORS="https://gitlab.com/workrr-trust/ledger.git https://codeberg.org/workrr-trust/ledger.git"
MIRRORS=${MIRRORS:-$DEFAULT_MIRRORS}

if [ -n "$MIRRORS" ]; then
  echo "== 3. mirrors: every copy's history must contain, or be contained in, this one"
  for m in $MIRRORS; do
    tip=$(git ls-remote "$m" refs/heads/main 2>/dev/null | cut -f1 || true)
    if [ -z "$tip" ]; then
      echo "   - $m (not yet initialized or unreachable; skipping)"
      continue
    fi
    git fetch --quiet "$m" main
    if git merge-base --is-ancestor "$tip" HEAD || git merge-base --is-ancestor HEAD "$tip"; then
      echo "   ✓ $m at ${tip:0:12}"
    else
      echo "   ✗ $m at ${tip:0:12} has DIVERGED from this clone"
      fails=$((fails + 1))
    fi
  done
fi

[ "$fails" -eq 0 ] && echo "AUDIT OK" || { echo "AUDIT FAILED"; exit 1; }
