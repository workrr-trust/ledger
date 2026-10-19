# Workrr Trust ledger

The public, append-only record of every [Workrr Trust](https://github.com/workrr-trust/certify)
certificate, plus our own witness record of the public Sigstore Rekor log that the
certificates are logged in.

**You don't have to trust this repo, or Workrr.** Every file here is checkable from
cryptography you get elsewhere: signatures chain to Sigstore's
[trusted root](https://github.com/sigstore/root-signing) (distributed via TUF), each
certificate re-verifies against its own source code, and the Rekor checkpoints are
signed by the log itself. The repo adds three things a signature can't: an index anyone
can browse, a history that would show it if the log ever forked, and copies that outlive
any single host. The design is in
[certify/docs/design.md §4–§6](https://github.com/workrr-trust/certify/blob/main/docs/design.md#4-witnesses).

## What's here

| Path | What it is |
|---|---|
| `certificates/sha256/<artifact digest>/<rekor log index>.sigstore.json` | One file per issued certificate: the Sigstore bundle exactly as the certifier produced it. It holds the DSSE-signed in-toto statement (the certificate), the Fulcio signing certificate, the Rekor entry, and its inclusion proof up to a signed checkpoint. Index only: artifacts are never copied here. The statement points to the source repo and commit. |
| `checkpoints/rekor.sigstore.dev/latest.txt` | The latest Rekor checkpoint we have verified (rekor-monitor format: the signed note with newlines escaped as `\n`). |
| `checkpoints/rekor.sigstore.dev/history/YYYY-MM.txt` | Every checkpoint we have committed, oldest first, as `<time observed, UTC> <checkpoint>`. Each one is proven consistent with the one before it. The chain starts at the inclusion checkpoint of the first certificate. |
| `anchors/YYYY-MM-DD.checkpoint.txt` + `.ots` | That day's latest checkpoint and its [OpenTimestamps](https://opentimestamps.org) proof, anchored in Bitcoin. |
| `tools/ckpt/` | A small Go tool that verifies checkpoint signatures (against the Rekor key in Sigstore's trusted root) and consistency proofs (fetched from Rekor, checked locally). |
| `scripts/` | `audit.sh` (check everything), `ingest.sh` (verify a submission), `commit.sh` (signed commits through the GitHub API). |
| `.github/workflows/` | `monitor` (hourly), `anchor` (daily), `ingest` (on submission). |
| `mirror/gitlab-ci.yml` | The GitLab mirror's fast-forward-only sync job. |

## Audit it

Everything below needs only `git`, `go` (1.25+), and `jq`, and talks only to GitHub
(for source code), Rekor, and the Sigstore TUF repository.

```sh
git clone https://github.com/workrr-trust/ledger && cd ledger
bash scripts/audit.sh
```

`audit.sh` builds `tools/ckpt` and the `workrr` CLI at the pinned certifier release
(`workrr-trust/certify` v0.1.0), then checks:

1. **The checkpoint chain.** Every committed checkpoint carries a valid Rekor
   signature. Each one is consistent with the next (an RFC 6962 consistency proof,
   verified locally). The live log is consistent with our latest checkpoint. If Rekor
   ever showed us one history and someone else another, one of these proofs would fail,
   and the evidence would stay in git.
2. **Every certificate.** For each file under `certificates/`, it fetches the source
   repo at the recorded commit and runs `workrr verify`. That re-hashes the artifact to
   the digest in the path, checks the Sigstore signature and Rekor inclusion proof, and
   checks the signer is the certifier the trust policy allows
   (`https://github.com/workrr-trust/certify/.github/workflows/certify.yml@refs/tags/v*`).
   Then it proves the certificate's inclusion checkpoint is consistent with the
   witnessed chain.
3. **Mirrors**, if you set `MIRRORS="<git url> …"`. Every mirror's history must
   contain this one or be contained in it.

To check one certificate by hand:

```sh
go install github.com/workrr-trust/certify/go/cmd/workrr@edf382958dd7ce070db0ed13af1cc8c31a150901
git clone https://github.com/workrr-trust/sample-skills && git -C sample-skills checkout f28a439723028c74dda64d5ce3ebe895a4167655
workrr verify sample-skills/skills/csv-summary \
  --bundle certificates/sha256/91cf3310705a521728b52c44f5e62df49767895e73eb0990d5ea739c7df8c884/3325986274.sigstore.json
```

You can also look up any entry on [search.sigstore.dev](https://search.sigstore.dev/?logIndex=3325986274)
or with `rekor-cli get --log-index <n>`.

To check an anchor:

```sh
pip install opentimestamps-client
ots verify anchors/2026-10-19.checkpoint.txt.ots     # needs a Bitcoin node, or upload the .ots at opentimestamps.org
```

A day's proof stays "pending" for a few hours until the calendar's Bitcoin transaction
confirms. The next daily run upgrades it to a full Bitcoin attestation.

Every commit in this repo is signed (GitHub shows it as Verified), because CI commits
through GitHub's API. `main` is protected against force-pushes and deletion, and requires
signed commits.

## How certificates get in

Nobody needs write access, including the certifier. A submission is only a pointer.

- Open an issue with the [**Submit a certificate**](../../issues/new?template=submit-certificate.yml)
  form (repo + artifact digest). Maintainers can also run the `ingest` workflow by hand.
- The `ingest` workflow fetches the certificate bundles for that digest from GitHub's
  public attestation store (`GET /repos/{repo}/attestations/sha256:{digest}`), where the
  certifier's `actions/attest` step put them. It indexes a bundle only if it is a Workrr
  certificate for exactly that digest, its source is that repo, `workrr verify` passes
  against a fresh checkout of the recorded commit, and its Rekor checkpoint is
  consistent with our witnessed chain. Nothing from the source repo is executed.
- The job that reads untrusted input has a read-only token. Only a separate job can
  write, and it only copies files matching `certificates/sha256/<hex>/<n>.sigstore.json`.
  The workflow then replies on the issue and closes it.

Bundles are self-verifying, so a malicious submitter can't get anything indexed that the
certifier didn't sign. At worst they waste a CI run.

## Self-witnessing Rekor

Public Rekor checkpoints are signed only by the log. Sigstore's witness cosigning is
planned but not live. Until it is, `monitor` runs hourly:

1. It runs [sigstore/rekor-monitor](https://github.com/sigstore/rekor-monitor), pinned
   by commit, against `latest.txt`. That verifies the log's new signed checkpoint and a
   consistency proof from our last one.
2. It checks the same pair again with `tools/ckpt`, an independent implementation.
3. It commits the new checkpoint to `latest.txt` and the month's history file.

On failure it opens a `monitor-failure` issue. We run rekor-monitor directly instead of
through its reusable workflow because that workflow keeps the previous checkpoint in a
14-day Actions artifact. Here the previous checkpoint lives in git, mirrored and archived.

When Sigstore ships witness cosignatures, we'll require them as well and keep this record.

Not yet covered: Rekor v2 shards (`logYYYY-N.rekor.sigstore.dev`). Sigstore's signing
config still points clients at v1, and every Workrr certificate so far is a v1 entry.
rekor-monitor's v2 mode will be added when certificates start landing there.

## Mirrors and archives

The mirrors are a durability layer, not the source of truth. Truth is the signatures and
proofs inside the files. Software Heritage is asked to archive the repo daily (Save Code
Now, from `anchor`). It keeps every snapshot it takes, so even a rewritten history leaves
evidence. These steps need accounts Workrr has to create by hand:

### GitLab (an independent witness: fast-forward only)

1. Create a gitlab.com account for Workrr (a role address, not a person), and turn on 2FA.
2. Create the public group **`workrr-trust`** (gitlab.com/groups/new).
3. New project → **Import project → Repository by URL**:
   `https://github.com/workrr-trust/ledger.git`, project name `ledger`, visibility
   **Public**. This is a one-time import. The sync job keeps it current.
4. **Settings → Repository → Protected branches**: `main`, Allowed to merge = Maintainers,
   Allowed to push and merge = Maintainers, **Allowed to force push = off**.
5. **Settings → Access tokens**: create a project access token named `mirror`, role
   **Maintainer**, scope **`write_repository`**, with the longest expiry allowed. Then
   **Settings → CI/CD → Variables**: add `MIRROR_PUSH_TOKEN` with that value,
   **Masked** and **Protected**.
6. **Settings → CI/CD → General pipelines → CI/CD configuration file**:
   `mirror/gitlab-ci.yml`.
7. **Build → Pipeline schedules → New schedule**: `0 */6 * * *`, target branch `main`.
   Run it once by hand and check it goes green.
8. Add `https://gitlab.com/workrr-trust/ledger.git` to `MIRRORS` in this README's audit
   example. Request a Software Heritage save for it at
   [archive.softwareheritage.org/save](https://archive.softwareheritage.org/save/).

If GitHub's history were ever rewritten, the job would fail and GitLab would keep the
original.

### Codeberg (non-profit mirror; durability only)

1. Create a codeberg.org account for Workrr, and turn on 2FA. Codeberg is for free and
   open-source projects, which this is.
2. Create the organization **`workrr-trust`** (codeberg.org/org/create), visibility public.
3. **+ → New migration → GitHub**: URL `https://github.com/workrr-trust/ledger`, no
   token needed (public repo). Owner `workrr-trust`, name `ledger`. Tick
   **"This repository will be a mirror"**, and migrate only the repository, without
   issues or pull requests.
4. In the new repo, **Settings → Mirror settings**: set the interval to `8h` (the
   default) or lower.
5. Request a Software Heritage save for `https://codeberg.org/workrr-trust/ledger`.

Forgejo pull mirrors follow upstream force-pushes, so Codeberg is a copy, not a witness.
The fast-forward-only witnesses are GitLab and Software Heritage's snapshots. Codeberg
can't sign either: public Sigstore Fulcio doesn't trust Codeberg's OIDC issuer yet.

## Limits

- The log proves Workrr *said* something and never changed its story. It doesn't make
  the checks correct. That comes from the public certifier code, the recorded tool
  digests, and re-running the checks.
- Revocations aren't recorded yet. A `revocations/` index and a signed trust-policy file
  arrive with certifier v0.2.
- Our self-witnessing is one more party watching the log. It isn't independent of
  Workrr. Mirrors on other forges, Software Heritage, and the Bitcoin anchors exist so
  that nobody needs to take our word for it, and so we can't quietly rewrite it.

Apache-2.0.
