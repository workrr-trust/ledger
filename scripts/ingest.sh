#!/usr/bin/env bash
# Find, verify and stage workrr certificates for one artifact digest.
#
#   scripts/ingest.sh <owner/repo> <sha256:hex> <out-dir>
#
# Pull, don't trust: the submitter only names a repository and a digest. The
# Sigstore bundles come from GitHub's public attestation store for that repo, and
# each one is indexed only if ALL of these hold:
#   1. it is a workrr certificate (predicateType) for exactly this digest;
#   2. its source is this repo, at a full commit SHA;
#   3. `workrr verify` passes against a fresh checkout of that commit: the
#      artifact re-hashes to the digest, the signature chains to Sigstore, the
#      Rekor inclusion proof is valid, and the signer is the certifier allowed by
#      the trust policy (workrr-trust/certify's certify.yml);
#   4. the Rekor checkpoint inside the bundle is consistent with the ledger's
#      latest witnessed checkpoint (tools/ckpt), so the certificate sits on the
#      same log history everyone else sees.
# Nothing from the source repo is executed; it is only checked out and hashed.
#
# Needs: gh (GH_TOKEN), jq, git, and `workrr` and `ckpt` on PATH. Run from the
# ledger root. Writes <out-dir>/certificates/... and <out-dir>/summary.md.
set -euo pipefail

repo=$1
digest=${2#sha256:}
out=$3
predicate_type=https://trust.workrr.ai/certificate/v0.1
latest=checkpoints/rekor.sigstore.dev/latest.txt

die() { echo "ingest: $*" >&2; echo "- ✗ $*" >>"$out/summary.md"; exit 1; }
mkdir -p "$out"
: >"$out/summary.md"

[[ $repo =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$ ]] || die "not a GitHub owner/repo: $repo"
[[ $digest =~ ^[0-9a-f]{64}$ ]] || die "not a sha256 digest: $2"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if ! gh api --paginate "repos/$repo/attestations/sha256:$digest" >"$work/pages.json" 2>"$work/err"; then
  die "no attestations for sha256:$digest in $repo ($(head -c 200 "$work/err"))"
fi
jq -c '.attestations[].bundle' "$work/pages.json" >"$work/bundles.jsonl"

found=0 added=0 n=0
while IFS= read -r bundle; do
  n=$((n + 1))
  b="$work/bundle-$n.json"
  printf '%s\n' "$bundle" >"$b"
  statement=$(jq -r '.dsseEnvelope.payload // empty' "$b" | base64 -d 2>/dev/null || true)
  [ "$(jq -r '.predicateType // empty' <<<"$statement" 2>/dev/null)" = "$predicate_type" ] || continue
  found=$((found + 1))

  log_index=$(jq -r '.verificationMaterial.tlogEntries[0].logIndex // empty' "$b")
  [[ $log_index =~ ^[0-9]{1,20}$ ]] || { echo "- ✗ bundle $n: no Rekor log index" >>"$out/summary.md"; continue; }
  dest="certificates/sha256/$digest/$log_index.sigstore.json"
  if [ -e "$dest" ]; then
    echo "- = already indexed: \`$dest\`" >>"$out/summary.md"
    continue
  fi

  subject=$(jq -r '[.subject[].digest.sha256] | join(",")' <<<"$statement")
  uri=$(jq -r '.predicate.source.uri // empty' <<<"$statement")
  commit=$(jq -r '.predicate.source.commit // empty' <<<"$statement")
  path=$(jq -r '.predicate.source.path // empty' <<<"$statement")
  fail() { echo "- ✗ Rekor $log_index: $*" >>"$out/summary.md"; }
  [ "$subject" = "$digest" ] || { fail "subject is not exactly sha256:$digest"; continue; }
  [ "$uri" = "https://github.com/$repo" ] || { fail "source $uri is not https://github.com/$repo"; continue; }
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || { fail "source commit is not a full SHA"; continue; }
  [[ $path =~ ^[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$ && ! /$path/ =~ /\.\.?/ ]] || { fail "unsafe source path"; continue; }

  src="$work/src-$commit"
  if [ ! -d "$src" ]; then
    git init --quiet "$src"
    git -C "$src" fetch --quiet --depth 1 "https://github.com/$repo" "$commit" || { fail "cannot fetch $commit"; continue; }
    git -C "$src" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
  fi
  [ -e "$src/$path" ] || { fail "$path not found at $commit"; continue; }

  if ! workrr verify "$src/$path" --bundle "$b" --json >"$work/verify-$n.json"; then
    fail "workrr verify failed: $(jq -c '[.bundles[].error // empty]' "$work/verify-$n.json" 2>/dev/null)"
    continue
  fi
  [ "$(jq -r '.artifactDigest' "$work/verify-$n.json")" = "$digest" ] || { fail "verified digest mismatch"; continue; }
  level=$(jq -r '.level' "$work/verify-$n.json")
  signer=$(jq -r '.bundles[0].signerIdentity' "$work/verify-$n.json")

  jq -r '.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope | gsub("\n"; "\\n")' "$b" >"$work/ckpt-$n.txt"
  if ! ckpt consistent "$work/ckpt-$n.txt" "$latest" >"$work/ckpt-$n.log" 2>&1; then
    fail "inclusion checkpoint not consistent with the witnessed log: $(tail -1 "$work/ckpt-$n.log")"
    continue
  fi

  mkdir -p "$out/$(dirname "$dest")"
  jq . "$b" >"$out/$dest"
  added=$((added + 1))
  echo "- ✓ \`$dest\` — level **$level**, Rekor log index [$log_index](https://search.sigstore.dev/?logIndex=$log_index), source $uri@${commit:0:12} \`$path\`, signer \`$signer\`" >>"$out/summary.md"
done <"$work/bundles.jsonl"

[ "$found" -gt 0 ] || die "no workrr certificates for sha256:$digest in $repo"
echo "$added" >"$out/count"
echo "ingest: $added new of $found workrr certificate(s) for sha256:$digest"
cat "$out/summary.md"
