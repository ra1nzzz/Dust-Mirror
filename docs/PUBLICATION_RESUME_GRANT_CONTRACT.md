# Publication resume grant contract

The normal `dustmirror.publication-authorization.v1` window is at most seven
days. It remains the immutable byte and identity ledger. If publication is
still partial after that window, it must **not** be made resumable by ignoring
the expiry or by reusing an old signature.

The protected Product signer may instead issue a canonical JSON
`dustmirror.publication-resume-grant.v1` plus an Ed25519 signature from the
same publication trust root. The grant is bound to:

- the SHA-256 of the original canonical publication authorization;
- Product commit, Product tree and candidate build ID;
- public Release commit and tree;
- tag and the exact CNB/GitHub targets;
- a monotonic resume sequence, nonce, issue time and expiry.

A grant is valid for at most 24 hours and has the fixed purpose
`resume-existing-partial-release`. It never authorizes creation of a new CNB
or GitHub Release. The consumer must first prove that an exact same-build
partial Release already exists, then accept only a preflight action of
`resume` or `resume_upload`. A `create` decision while `resume_only=true` is a
hard failure.

Public verification support lives in
`scripts/verify_publication_resume_grant.py` and the optional
`--resume-grant` / `--resume-grant-signature` inputs of
`scripts/verify_publication_authorization.py`. A rerun may set the validated
`PUBLICATION_RESUME_GRANT_ID`; the public pipeline then downloads exactly
`DustMirror-publication-resume-grant-<id>.json/.sig` from the same pinned
Product commit, verifies the signature and exports `resume_only=true`. A
dedicated stage hard-rejects `create` and permits only `resume` or
`resume_upload`.

The current Product/Signer workflow does not yet mint or upload those two
fresh attachments. Enabling the post-seven-day path therefore still requires
that cross-repository producer integration. Until it exists, an expired
authorization has no grant ID and continues to fail closed.
