# Non-production record examples

Files in this directory demonstrate the exact JSON shape only. Their hashes,
identities, nonces, and signatures are deliberately inert and MUST NOT be
copied into `governance/approvals` or `governance/receipts`.

Use `governance/ledger.py` with a separately provisioned 2-of-N Ed25519
keyring. The checked-in policy remains `provisioning_required` until real
offline public keys are reviewed and activated.
