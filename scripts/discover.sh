#!/usr/bin/env bash
# Find new workrr certificates without anyone submitting them.
#
#   scripts/discover.sh <days> <out.json>
#
# Watched repos: those listed in sources.txt (opt-in, by pull request) plus every
# repo that already has a certificate in the ledger. For each one, it lists the
# `workrr-certificate` artifacts the certifier uploaded in the last <days> days,
# reads the artifact digest from each, and asks GitHub's attestation store which
# workrr certificates exist for that digest. Every repo + digest that has one not
# yet under certificates/ goes to <out.json> as [{repository, digest}], for the
# ingest workflow to verify from scratch.
#
# Public scans (workrr-trust/certify's scan.yml) are found differently, since they
# run in batches of up to 50: each scan.yml run completed in the last
# OBSERVER_MINUTES (default 60) uploads one `workrr-scan-index` artifact listing
# digest, predicate type (certificate or finding) and Rekor log index per target.
# A record whose file isn't in certificates/ or findings/ yet goes to ingest.
#
# Discovery is permissive on purpose: the artifacts are untrusted and only used to
# learn digests, and nothing is indexed unless scripts/ingest.sh verifies it.
# Nothing from a watched repo is executed.
#
# Needs: gh (GH_TOKEN), jq, unzip. Run from the ledger root.
set -euo pipefail

days=$1
out=$2
predicate_type=https://trust.workrr.ai/certificate/v0.1
finding_type=https://trust.workrr.ai/finding/v0.1
OBSERVER_STORE=workrr-trust/certify
repo_re='^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$'
since=$(jq -nr --argjson d "$days" 'now - $d * 86400 | todate')

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

{
  sed -e 's/#.*//' -e 's/[[:space:]]//g' sources.txt 2>/dev/null || true
  for f in certificates/sha256/*/*.sigstore.json; do
    [ -e "$f" ] || continue
    # Public scans name the scanned repo, but their certificates live in workrr-trust/certify
    # (listed in sources.txt), so they don't make that repo a watched one.
    jq -r '.dsseEnvelope.payload' "$f" | base64 -d | jq -r 'select(.predicate.level != "scanned") | .predicate.source.uri // empty'
  done | sed 's|^https://github.com/||'
} | awk 'NF' | sort -fu >"$work/repos"

: >"$work/pairs"
while IFS= read -r repo; do
  [[ $repo =~ $repo_re ]] || { echo "skip: not owner/repo: $repo"; continue; }
  if ! gh api --paginate "repos/$repo/actions/artifacts?name=workrr-certificate&per_page=100" \
    --jq ".artifacts[] | select(.expired | not) | select(.created_at >= \"$since\") | select(.size_in_bytes < 1000000) | .id" \
    >"$work/ids" 2>"$work/err"; then
    echo "skip: $repo: $(head -c 200 "$work/err")"
    continue
  fi
  echo "$repo: $(wc -l <"$work/ids" | tr -d ' ') certificate artifact(s) since $since"
  while IFS= read -r id; do
    rm -f "$work/a.zip"
    gh api "repos/$repo/actions/artifacts/$id/zip" >"$work/a.zip" 2>/dev/null || { echo "  skip artifact $id: download failed"; continue; }
    unzip -p "$work/a.zip" statement.json 2>/dev/null | head -c 1000000 |
      jq -r '.subject[]?.digest.sha256 // empty' 2>/dev/null |
      grep -E '^[0-9a-f]{64}$' | sed "s|^|$repo |" >>"$work/pairs" || true
  done <"$work/ids"
done <"$work/repos"

: >"$work/new"
sort -u "$work/pairs" | while read -r repo digest; do
  if ! gh api --paginate "repos/$repo/attestations/sha256:$digest" >"$work/att.json" 2>/dev/null; then
    echo "  $repo sha256:${digest:0:12}: not in the attestation store"
    continue
  fi
  pending=0
  for idx in $(jq -r --arg pt "$predicate_type" '.attestations[].bundle
      | select((.dsseEnvelope.payload | @base64d | fromjson | .predicateType) == $pt)
      | .verificationMaterial.tlogEntries[0].logIndex' "$work/att.json" 2>/dev/null | grep -E '^[0-9]{1,20}$'); do
    if [ -e "certificates/sha256/$digest/$idx.sigstore.json" ]; then
      echo "  $repo sha256:${digest:0:12}: Rekor $idx already indexed"
    else
      echo "  $repo sha256:${digest:0:12}: Rekor $idx is new"
      pending=1
    fi
  done
  [ "$pending" -eq 0 ] || echo "$repo sha256:$digest" >>"$work/new"
done

# Public scans: one index artifact per scan.yml run.
obs_since=$(jq -nr --argjson m "${OBSERVER_MINUTES:-60}" 'now - $m * 60 | todate')
if gh api --paginate "repos/$OBSERVER_STORE/actions/workflows/scan.yml/runs?status=completed&per_page=100&created=>=$obs_since" \
  --jq '.workflow_runs[].id' >"$work/runs" 2>"$work/err"; then
  echo "$OBSERVER_STORE: $(wc -l <"$work/runs" | tr -d ' ') scan run(s) since $obs_since"
  while IFS= read -r run; do
    id=$(gh api "repos/$OBSERVER_STORE/actions/runs/$run/artifacts?name=workrr-scan-index" --jq '.artifacts[0] | select(.expired | not) | .id' 2>/dev/null) || continue
    [ -n "$id" ] || continue
    rm -f "$work/a.zip"
    gh api "repos/$OBSERVER_STORE/actions/artifacts/$id/zip" >"$work/a.zip" 2>/dev/null || { echo "  skip run $run: download failed"; continue; }
    unzip -p "$work/a.zip" index.jsonl 2>/dev/null | head -c 1000000 |
      jq -r --arg ct "$predicate_type" --arg ft "$finding_type" '
        select(.digest | test("^[0-9a-f]{64}$")) | select(.logIndex | tostring | test("^[0-9]{1,20}$"))
        | [(if .predicateType == $ct then "certificates" elif .predicateType == $ft then "findings" else empty end), .digest, (.logIndex | tostring)]
        | @tsv' 2>/dev/null |
      while IFS=$'\t' read -r kind digest idx; do
        [ -e "$kind/sha256/$digest/$idx.sigstore.json" ] || echo "$OBSERVER_STORE sha256:$digest"
      done >>"$work/new" || true
  done <"$work/runs"
else
  echo "skip: $OBSERVER_STORE scan runs: $(head -c 200 "$work/err")"
fi

sort -u "$work/new" -o "$work/new"
jq -Rn '[inputs | split(" ") | {repository: .[0], digest: .[1]}]' <"$work/new" >"$out"
echo "discover: $(jq length "$out") repo+digest pair(s) to ingest"
