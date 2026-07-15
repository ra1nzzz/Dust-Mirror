# DustMirror public trust ledger

This public repository is the trust root for the GitHub Free governance mode.
The private `DustMirror-Dev`, `DustMirror`, and `DustMirror-Pro-Get`
repositories are candidate source or artifact carriers: their default branches,
tags, releases, and workflow results are not trusted by themselves.

**Current state: `REMOTE_ACTIVATION_PENDING`.** `policy.json` deliberately has
`activation_status=provisioning_required`, threshold 2, and no public keys.
This makes the repository safe to merge before key ceremony: schema and tests
work, but every approval, receipt, sync, publish, OTA, and PRO install must fail
closed until two real offline Ed25519 public keys are reviewed and activated.
Test keys in `tests/` are never a production trust root.

A source revision becomes eligible for synchronization or publication only
when an approval record for its exact commit and tree SHA is merged into this
repository's protected `main` branch. The record binds the policy epoch,
required successful checks, target repository/base, release identity, and a
unique nonce. Privileged workflows consume the record exactly once (release)
or idempotently against the recorded target base (sync) and write a receipt.

## Why this exists

GitHub Free cannot enforce branch or tag rulesets, protected branches, required
reviewers, or protected environment secrets on private repositories. It can
enforce those controls on a public repository. The trust boundary is therefore
moved here without publishing private source code.

Direct pushes to a private repository may still exist, but they cannot enter a
trusted sync, FREE release, PRO release, OTA update, or module installation
unless the exact content is anchored here. A moved private tag or replaced PRO
asset is rejected when its digest does not match the public approval/receipt.

## Approval lifecycle

1. Private repositories run unprivileged candidate CI and expose no cross-repo
   write or signing secret.
2. A maintainer creates one JSON record under
   `governance/approvals/<kind>/<approval-id>.json`.
3. The public pull request is validated by trusted code from the ledger base
   branch and reviewed by an independent collaborator.
4. Protected `main` accepts the record only after `ledger-static` succeeds and
   all review requirements pass.
5. A protected public environment runs the corresponding workflow. It checks
   the exact private commit/tree/check-runs again, builds without write secrets,
   and publishes in a separate job that never executes candidate code.
6. The workflow writes a receipt under `governance/receipts/` and emits public
   provenance. Reusing a single-use approval is rejected.

Approval and receipt envelopes contain a canonical `statement` plus signatures
sorted by distinct `key_id`. `dustmirror-cjson-v1` rejects duplicate JSON keys,
floats/non-finite numbers, non-NFC strings, unknown fields, and non-canonical
identity fields. The Ed25519 signature input is exactly the UTF-8 canonical
statement; chain `prev` values use the SHA-256 of the complete prior envelope.
The schemas are documentation; `governance/ledger.py` is the fail-closed
semantic validator.

`pull_request_target` is used only for the public `ledger-static` gate. Every
command and dependency lock comes from the protected base SHA. The candidate
checkout is parsed as data, receives no secret, has a read-only token, and is
never imported or executed. Existing ledger records and policy snapshots are
append-only. A live-record PR cannot change code, workflows, policy, or docs.

## Local verification

```powershell
python governance/ledger.py policy-digest
python governance/ledger.py validate-tree
python -m unittest discover -s tests -v
python governance/validate_pr.py --base . --candidate .
```

Ed25519 validation requires `cryptography`. GitHub-hosted Ubuntu installs the
CPython 3.11 dependency set from the hash-locked
`governance/requirements-ci-linux.lock` file.

## Key activation and rotation

The initial activation is a dedicated PR containing only:

- an active `governance/policy.json` with at least two independently held
  Ed25519 public keys; and
- the identical immutable `governance/policies/epoch-1.json` snapshot.

Do not generate or store private keys in this repository, Actions, a shared
password manager entry, or the same device. After activation, every rotation
increments the epoch and adds exactly one immutable policy snapshot plus
`governance/policy-transitions/epoch-N.json`, signed at the old threshold.
Repository identities and ledger paths cannot be redirected by a rotation.

## Required public-repository controls

- Apply `.github/rulesets/ledger-main.json` and
  `.github/rulesets/immutable-tags.json` with no bypass actors.
- Add an independent collaborator before requiring one approval; the PR author
  cannot approve their own change.
- Create `approval-verification`, `sync-production`, `free-production`, and
  `pro-production` environments. Require a reviewer and disallow self-review.
- Store only narrowly scoped GitHub App credentials in those environment
  secrets. Remove `CROSS_REPO_TOKEN`, release App keys, and `OTA_SIGNING_KEY`
  from the private repositories after migration.
- Give publisher Apps no Administration permission and no ruleset bypass. A
  FREE publisher may write Release assets in this same repository, but clients
  trust only a signed ledger digest; asset replacement therefore fails closed.

The public record exposes repository names, commit/tree hashes, versions,
check-run identifiers, and artifact digests. It never contains private source,
API keys, signing keys, user data, or PRO module bytes.
