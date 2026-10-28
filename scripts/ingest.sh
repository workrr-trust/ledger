#!/usr/bin/env bash
# Find, verify and stage workrr certificates and findings for one artifact digest.
#
#   scripts/ingest.sh <owner/repo> <sha256:hex> <out-dir>
#
# Pull, don't trust: the submitter only names a repository and a digest. The
# Sigstore bundles come from GitHub's public attestation store for that repo, and
# each one is indexed only if ALL of these hold:
#   1. it is a workrr certificate (predicateType) for exactly this digest;
#   2. its source is this repo, at a full commit SHA. The exception is workrr's public
#      scans (docs/public-scans.md in workrr-trust/certify): their attestations live
#      in OBSERVER_STORE and name the scanned repo as source, and the verifier accepts
#      them only from the observer signer at level "scanned";
#   3. `workrr verify` passes against a fresh checkout of that commit: the
#      artifact re-hashes to the digest, the signature chains to Sigstore, the
#      Rekor inclusion proof is valid, and the signer is the certifier allowed by
#      the trust policy (workrr-trust/certify's certify.yml);
#   4. the Rekor checkpoint inside the bundle is consistent with the ledger's
#      latest witnessed checkpoint (tools/ckpt), so the certificate sits on the
#      same log history everyone else sees.
# Findings (docs/findings.md in workrr-trust/certify) are what a public scan signs
# when a security check fails. They come only from OBSERVER_STORE and are indexed
# under findings/ only if `workrr verify-finding` passes: signature, Rekor and
# observer signer as above, and the finding REPRODUCES (the same checks, re-run on
# a fresh checkout of the commit, fail in exactly the same way). Check 4 applies too.
# A certificate from the GitLab witness (docs/gitlab-certifier.md in
# workrr-trust/certify) verifies alone as "scanned". When one is indexed, every
# certificate for the digest is also verified together; if the publisher's GitHub
# certificate and the witness agree, the witness record's level is "gold"
# (Reproduced): the record that completed it.
# Nothing from the source repo is executed; it is only checked out and hashed.
#
# Needs: gh (GH_TOKEN), jq, git, and `workrr` and `ckpt` on PATH. Run from the
# ledger root. Writes <out-dir>/certificates/..., <out-dir>/findings/...,
# <out-dir>/summary.md, and <out-dir>/index.jsonl: one line per new record, read by
# the site instead of every bundle (fields: kind, file, digest, logIndex, time,
# name, type, level, band, source, signer; findings add findingKind and findings).
set -euo pipefail

repo=$1
digest=${2#sha256:}
out=$3
predicate_type=https://trust.workrr.ai/certificate/v0.1
finding_type=https://trust.workrr.ai/finding/v0.1
OBSERVER_STORE=workrr-trust/certify
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
certs=() witnesses=()
while IFS= read -r bundle; do
  n=$((n + 1))
  b="$work/bundle-$n.json"
  printf '%s\n' "$bundle" >"$b"
  statement=$(jq -r '.dsseEnvelope.payload // empty' "$b" | base64 -d 2>/dev/null || true)
  case "$(jq -r '.predicateType // empty' <<<"$statement" 2>/dev/null)" in
    "$predicate_type") kind=certificates ;;
    "$finding_type") kind=findings ;;
    *) continue ;;
  esac
  found=$((found + 1))
  [ "$kind" = certificates ] && certs+=("$b")

  log_index=$(jq -r '.verificationMaterial.tlogEntries[0].logIndex // empty' "$b")
  [[ $log_index =~ ^[0-9]{1,20}$ ]] || { echo "- ✗ bundle $n: no Rekor log index" >>"$out/summary.md"; continue; }
  dest="$kind/sha256/$digest/$log_index.sigstore.json"
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
  if [ "$kind" = findings ] && [ "$repo" != "$OBSERVER_STORE" ]; then
    fail "findings come only from $OBSERVER_STORE"
    continue
  fi
  if [ "$repo" = "$OBSERVER_STORE" ]; then
    [[ $uri =~ ^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$ ]] || { fail "source $uri is not a GitHub repo"; continue; }
    [ "$kind" = findings ] || [ "$(jq -r '.predicate.level // empty' <<<"$statement")" = scanned ] || { fail "certificate in $OBSERVER_STORE is not a public scan"; continue; }
  else
    [ "$uri" = "https://github.com/$repo" ] || { fail "source $uri is not https://github.com/$repo"; continue; }
  fi
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || { fail "source commit is not a full SHA"; continue; }
  # "." is a whole-repo artifact; any other "." or ".." segment is refused.
  [[ $path == . || ( $path =~ ^[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$ && ! /$path/ =~ /\.\.?/ ) ]] || { fail "unsafe source path"; continue; }

  src="$work/src-$commit"
  if [ ! -d "$src" ]; then
    git init --quiet "$src"
    git -C "$src" fetch --quiet --depth 1 "$uri" "$commit" || { fail "cannot fetch $commit"; continue; }
    git -C "$src" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
  fi
  [ -e "$src/$path" ] || { fail "$path not found at $commit"; continue; }

  if [ "$kind" = findings ]; then
    if ! workrr verify-finding "$src/$path" --bundle "$b" --json >"$work/verify-$n.json"; then
      fail "workrr verify-finding failed: $(jq -r '.error // "no result"' "$work/verify-$n.json" 2>/dev/null)"
      continue
    fi
    level="flagged ($(jq -r '.kind' "$work/verify-$n.json"): $(jq -r '[.findings[] | .detail + " " + (.file // "") + (if .line then ":\(.line)" else "" end)] | join("; ")' "$work/verify-$n.json"))"
    signer=$(jq -r '.signerIdentity' "$work/verify-$n.json")
  else
    if ! workrr verify "$src/$path" --bundle "$b" --json >"$work/verify-$n.json"; then
      fail "workrr verify failed: $(jq -c '[.bundles[].error // empty]' "$work/verify-$n.json" 2>/dev/null)"
      continue
    fi
    level=$(jq -r '.level' "$work/verify-$n.json")
    signer=$(jq -r '.bundles[0].signerIdentity' "$work/verify-$n.json")
  fi
  [ "$(jq -r '.artifactDigest' "$work/verify-$n.json")" = "$digest" ] || { fail "verified digest mismatch"; continue; }

  jq -r '.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope | gsub("\n"; "\\n")' "$b" >"$work/ckpt-$n.txt"
  if ! ckpt consistent "$work/ckpt-$n.txt" "$latest" >"$work/ckpt-$n.log" 2>&1; then
    fail "inclusion checkpoint not consistent with the witnessed log: $(tail -1 "$work/ckpt-$n.log")"
    continue
  fi

  if [ "$kind" = certificates ] && [ "$(jq -r '.bundles[0].witness // false' "$work/verify-$n.json")" = true ]; then
    witnesses+=("$dest $src/$path")
  fi

  mkdir -p "$out/$(dirname "$dest")"
  jq . "$b" >"$out/$dest"
  jq -c --arg kind "${kind%s}" --arg file "$dest" --arg digest "$digest" --arg idx "$log_index" \
    --arg signer "$signer" --arg level "$(jq -r '.level // empty' "$work/verify-$n.json")" \
    --argjson time "$(jq '.verificationMaterial.tlogEntries[0].integratedTime // "0" | tonumber' "$b")" \
    '{kind: $kind, file: $file, digest: $digest, logIndex: $idx, time: $time,
      name: (.subject[0].name // ""), type: (.predicate.artifact.type // ""),
      level: (if $kind == "finding" then "flagged" else $level end), band: (.predicate.band // ""),
      source: .predicate.source, signer: $signer}
     + (if $kind == "finding" then {findingKind: .predicate.kind, findings: .predicate.findings} else {} end)' \
    <<<"$statement" >>"$out/index.jsonl"
  added=$((added + 1))
  echo "- ✓ \`$dest\` — level **$level**, Rekor log index [$log_index](https://search.sigstore.dev/?logIndex=$log_index), source $uri@${commit:0:12} \`$path\`, signer \`$signer\`" >>"$out/summary.md"
done <"$work/bundles.jsonl"

# Reproduced: verify the new witness certificates together with every certificate
# for this digest.
for w in ${witnesses[@]+"${witnesses[@]}"}; do
  read -r dest artifact <<<"$w"
  args=()
  for b in "${certs[@]}"; do args+=(--bundle "$b"); done
  if workrr verify "$artifact" "${args[@]}" --json >"$work/gold.json" 2>/dev/null &&
    [ "$(jq -r .level "$work/gold.json")" = gold ]; then
    jq -c --arg f "$dest" 'if .file == $f then .level = "gold" else . end' "$out/index.jsonl" >"$work/index.jsonl"
    mv "$work/index.jsonl" "$out/index.jsonl"
    echo "- ★ \`$dest\` — the publisher's certificate and the GitLab witness agree: level **gold** (Reproduced)" >>"$out/summary.md"
  else
    echo "- = \`$dest\` — witness only: $(jq -r '[.notes[]?] | join("; ")' "$work/gold.json" 2>/dev/null)" >>"$out/summary.md"
  fi
done

[ "$found" -gt 0 ] || die "no workrr certificates or findings for sha256:$digest in $repo"
echo "$added" >"$out/count"
echo "ingest: $added new of $found workrr certificate(s) and finding(s) for sha256:$digest"
cat "$out/summary.md"
