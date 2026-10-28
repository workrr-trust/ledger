#!/usr/bin/env bash
# Find GitLab witness certificates for one artifact digest.
#
#   scripts/witness.sh <hex digest> [<out-dir>]
#
# The witness (docs/gitlab-certifier.md in workrr-trust/certify) signs on GitLab CI,
# and GitHub's attestation store only accepts certificates GitHub issued, so a
# witness bundle stays where it was made: the public `workrr-certify` job artifact
# in gitlab.com/workrr-trust/certify-gitlab. Rekor indexes every entry by subject
# digest, and the Fulcio certificate in the entry names the job that signed it
# (Run Invocation URI). This follows that pointer: digest → Rekor entries signed
# by the witness identity → job → certificate.sigstore.json.
#
# Prints the Rekor log index of each witness entry. With <out-dir>, also downloads
# each bundle to <out-dir>/<logIndex>.sigstore.json when its log index matches the
# entry. Everything here is untrusted until scripts/ingest.sh verifies it.
#
# Needs: curl, jq, openssl.
set -euo pipefail

digest=$1
out=${2:-}
[[ $digest =~ ^[0-9a-f]{64}$ ]] || { echo "witness: not a sha256 digest: $digest" >&2; exit 1; }
rekor=https://rekor.sigstore.dev/api/v1
project=https://gitlab.com/api/v4/projects/workrr-trust%2Fcertify-gitlab
san_re='^ *URI:https://gitlab\.com/workrr-trust/certify-gitlab//\.gitlab-ci\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
job_re='https://gitlab\.com/workrr-trust/certify-gitlab/-/jobs/([0-9]{1,20})'

uuids=$(curl -fsS -X POST "$rekor/index/retrieve" -H 'content-type: application/json' \
  -d "{\"hash\":\"sha256:$digest\"}" | jq -r '.[]? | select(test("^[0-9a-f]{64,80}$"))')
for uuid in $(head -200 <<<"$uuids"); do
  entry=$(curl -fsS "$rekor/log/entries/$uuid") || continue
  idx=$(jq -r '.[].logIndex' <<<"$entry")
  [[ $idx =~ ^[0-9]{1,20}$ ]] || continue
  cert=$(jq -r '.[].body' <<<"$entry" | base64 -d | jq -r 'select(.kind == "dsse") | .spec.signatures[0].verifier // empty')
  [ -n "$cert" ] || continue
  text=$(base64 -d <<<"$cert" | openssl x509 -noout -text 2>/dev/null) || continue
  grep -Eq "$san_re" <<<"$text" || continue
  [[ $text =~ $job_re ]] || continue
  job=${BASH_REMATCH[1]}
  echo "$idx"
  [ -n "$out" ] || continue
  mkdir -p "$out"
  # The ledger's copy, once indexed: GitLab limits unauthenticated downloads per IP,
  # and a download refused now is retried on discover's next run.
  # Read from git, not the working tree: CI checks out without certificates/.
  if git show "HEAD:certificates/sha256/$digest/$idx.sigstore.json" >"$out/$idx.sigstore.json" 2>/dev/null; then
    continue
  fi
  rm -f "$out/$idx.sigstore.json"
  if ! curl -fsSL --retry 2 --retry-max-time 60 --max-filesize 1000000 -o "$out/$idx.tmp" \
    "$project/jobs/$job/artifacts/certificate/certificate.sigstore.json"; then
    echo "witness: Rekor $idx: no certificate from job $job" >&2
  elif [ "$(jq -r '.verificationMaterial.tlogEntries[0].logIndex // empty' "$out/$idx.tmp" 2>/dev/null)" = "$idx" ]; then
    mv "$out/$idx.tmp" "$out/$idx.sigstore.json"
    continue
  else
    echo "witness: Rekor $idx: job $job's certificate is a different entry" >&2
  fi
  rm -f "$out/$idx.tmp"
done
