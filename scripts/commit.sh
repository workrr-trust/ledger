#!/usr/bin/env bash
# Commit files to the ledger through GitHub's GraphQL API (createCommitOnBranch),
# so every ledger commit is signed by GitHub and shows as Verified. A plain
# `git push` from CI would produce unsigned commits, which the ruleset rejects.
#
#   scripts/commit.sh "<headline>" <path>...
#
# Paths are added or replaced (the ledger never deletes). Needs GH_TOKEN with
# contents:write and GITHUB_REPOSITORY. The commit is made on top of the local
# HEAD; if another writer moved the branch meanwhile, it is retried on the new
# tip only when that writer touched none of our paths, so nothing is clobbered.
set -euo pipefail

headline=$1
shift
[ $# -gt 0 ] || { echo "commit.sh: nothing to commit" >&2; exit 1; }
branch=${LEDGER_BRANCH:-main}
head=$(git rev-parse HEAD)

# File contents go through temp files, never command-line arguments: Linux caps a
# single argument at 128 KiB, and the monthly checkpoint history outgrows that.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for p in "$@"; do
  base64 <"$p" | tr -d '\n' >"$tmp/b64"
  jq -n --arg path "$p" --rawfile contents "$tmp/b64" '{path: $path, contents: $contents}'
done | jq -s . >"$tmp/additions.json"

for attempt in 1 2 3 4 5; do
  if jq -n \
    --arg repo "$GITHUB_REPOSITORY" --arg branch "$branch" --arg head "$head" \
    --arg headline "$headline" --arg body "${COMMIT_BODY:-}" --slurpfile additions "$tmp/additions.json" \
    '{
      query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid url } } }",
      variables: {input: {
        branch: {repositoryNameWithOwner: $repo, branchName: $branch},
        expectedHeadOid: $head,
        message: {headline: $headline, body: $body},
        fileChanges: {additions: $additions[0]}
      }}
    }' | gh api graphql --input - --jq '.data.createCommitOnBranch.commit | "committed \(.oid) \(.url)"'; then
    git fetch --quiet origin "$branch"
    git reset --quiet --hard FETCH_HEAD
    exit 0
  fi
  git fetch --quiet origin "$branch"
  tip=$(git rev-parse FETCH_HEAD)
  [ "$tip" != "$head" ] || { echo "commit.sh: commit failed (branch did not move)" >&2; exit 1; }
  if ! git diff --quiet "$head" "$tip" -- "$@"; then
    echo "commit.sh: $branch moved to $tip and changed our paths; refusing to overwrite" >&2
    exit 1
  fi
  echo "commit.sh: $branch moved to $tip (other paths only); retrying ($attempt)" >&2
  head=$tip
  sleep $((attempt * 2))
done
exit 1
