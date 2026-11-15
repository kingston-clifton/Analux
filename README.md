
© 2026 Kingston Clifton, © 2026 Analux

https://analux.xyz/
https://zenodo.org/records/24117466

Questions? Concerns?
Contacts:
kingstonclifton1@gmail.com
analuxsupport@gmail.com


Designed and Made with love by Kingston Clifton 


NOTE FOR GRANT REVIEWERS: To protect our un-audited core program logic from automated scraper bots and front-running bots prior to our security audit, our on-chain Rust programs and smart contracts are temporarily maintained in a private core repository. The public repository contains our workspace architecture, client side tooling, IDLs, and test suites. Read only access to the private repo with the smart contracts are available to reviewers upon request. 


# Analux Q-Chain — V6 contracts

An executable Solana Contract Regarding Q-Vault MSS. The program uses real compressed Falcon-512 verification, although it does not accept an oracle verdict, administrator signature, or placeholder verifier.

Source is isolated in this directory. The existing website is independent. Nothing here deploys a program, broadcasts transactions, or modifies a live token.



## Contents

| File | Purpose |
| --- | --- |
| `programs/analux/src/lib.rs` | Anchor entrypoints, PDA constraints, custody, and SPL token CPIs |
| `programs/analux/src/crypto.rs` | Canonical enrollment/transfer transcripts, SHA-256 stitching, real Falcon verification |
| `programs/analux/src/guards.rs` | Ed25519 precompile binding, mandatory priority fee, authenticated temporal anchor |
| `programs/analux/src/state.rs` | Immutable ADKI identity, persistent vault nonce, bounded upload accounts |
| `tests/src/lib.rs` | Rust instruction builders; no RPC, secret handling, signing, or submission |
| `tests/tests/security.rs` | Real PQClean/Falcon interoperability and transcript/adversarial tests |
| `tests/tests/svm.rs` | Actual SBF execution in LiteSVM, including the Ed25519 precompile and SPL CPIs |


## Instructions

* `begin_upload(object_hash, expected_len)` creates an uploader-funded PDA for a 897-byte Falcon public key or 666-byte compressed signature.
* `append_upload(offset, bytes)` appends up to 700 bytes in order. Completion checks the committed content hash. Partial or overwritten content cannot authorize a transfer.
* `close_upload()` refunds buffer rent to its uploader. It never touches custody assets.
* `enroll_vault(key_hash, deployment_domain)` requires the Ed25519 owner to sign and a valid Falcon proof of possession binding the owner, mint, program, vault address, and deployment domain. Both key and proof are staged in upload accounts.
* `open_custody_account()` creates the canonical SPL token ATA for the QVault PDA. It is idempotent, including if the ATA was created in advance.
* `deposit(amount)` transfers standard SPL tokens into custody. Only the depositing token account's signer can deposit from it.
* `execute_transfer(intent, ed_signature)` is the only custody release path. It requires Ed25519 and Falcon authorization as well as a live temporal anchor, the next nonce, and mandatory validator priority fees. Destination may be another Q-Vault's ATA or an ordinary token account.
* `create_asset(asset_id, decimals, supply)` optionally creates a standard fixed-supply SPL mint, distributes initial supply to its creator, and permanently revokes mint authority. There is no freeze authority. **This smart contract and the V6 whitepaper do not specify supply or decimals as they remain explicit caller choices.** This factory is permissionless and does not designate an official mint.

## Build and test

Toolchain: Anchor 0.32.1; Rust; a compatible `cargo-build-sbf`; Cargo.lock is included. The installed legacy Solana 1.18 CLI alone cannot build the edition-2024 Falcon dependency. No wallet keypair is required to compile or run these tests.

```sh
cd [The Smart Contract, wherever that might be...]
NO_DNA=1 cargo test --workspace --locked
SBF_PLATFORM_TOOLS=/absolute/path/to/platform-tools sh scripts/build-sbf.sh --offline
NO_DNA=1 cargo test -p analux-tests --features svm-tests --test svm --locked -- --nocapture
```
Note:

Please replace /absolute/path/to/platform-tools with your own path, as well as [The Smart Contract, wherever that might be...] with the smart contract repository. 

Use the extracted Anza **platform-tools v1.54** distribution for your OS/architecture. Set `ANALUX_PROGRAM_SO` to an absolute `.so` path when it is outside `target/deploy`. The SVM suite asserts that its actual serialized legacy transactions are at most 1,232 bytes. These tests run entirely inside a local VM with ephemeral synthetic test credentials. Generated JSON/TypeScript interfaces are included under `idl/`; regenerate with `NO_DNA=1 anchor idl build -p analux -o idl/analux.json -t idl/analux.ts`.

## Using Q-Vault

1. Select a standard SPL mint with revoked freeze authority; optionally create a new fixed-supply mint using `create_asset`. Token-2022 is not accepted.
2. Obtain Falcon-512 public key bytes from an external signer. Upload the public key. Its 32-byte SHA-256 hash identifies the vault.
3. Derive `(vault, bump) = find_program_address([b"QVault", key_hash], program_id)`.
4. Choose a deployment domain (normally the cluster genesis hash). Have the external Falcon signer sign `enrollment_digest(...)`. Upload that compressed proof and enroll with the Ed25519 owner's wallet signature.
5. Create custody ATA and deposit. Key/proof buffers may now be closed by their funder.
6. For a release, fetch the vault's nonce and an actual `(slot, hash)` from the canonical SlotHashes sysvar. Choose `valid_until_slot` no later than `anchor_slot + 150`; allow time for staging.
7. Compute `intent_digest(...)`. Obtain an Ed25519 signature over these **32 bytes**. Compute `stitched_digest(...)`, then obtain a Falcon signature over those **32 bytes**. Signers must not add an unrequested text prefix or rehash the digest themselves.
8. Upload the compressed Falcon signature. Build the four instructions below, simulate the complete transaction, and then have the sponsor's wallet sign it. Rebuild and re-sign if the anchor expires or nonce changes.

```
0  ComputeBudget: SetComputeUnitLimit
1  ComputeBudget: SetComputeUnitPrice
2  Ed25519 precompile: verify owner / signature / intent_digest
3  Analux: execute_transfer
```

The requested compute budget and price must produce at least **1,000,000 lamports (0.001 SOL)** in native priority fees. For example, 500,000 CU × 2,000,000 micro-lamports/CU = 1,000,000 lamports. This is a validator fee, as it is responsible for the compute required for the Q-Vault MSS. Actual consumed CU and requested CU are different quantities. Staging/enrollment have their own ordinary transaction/rent costs; DQIP applies to protected releases. (Again, DQIP covers the  CU costs).

Falcon encoding is legacy compressed `0x39`, zero-extended to 666 bytes. Public keys use the 897-byte `0x09` format. Padded `0x49`, Falcon-1024, and future FN-DSA formats are not interchangeable. A signer must retry the uncommon compressed signature longer than 666 bytes and  never truncate it.

## Scope and custody boundaries

The PDA protects balances held inside its token account (hence the vault), tokens withdrawn to a conventional wallet resume standard SPL authorization. This means that an ordinary SPL mint cannot make every transfer on Solana quantum-resistant. Registration commits one mint per Falcon identity, matching V6's key-hash-only PDA seeds. Migrate to a newly enrolled Falcon identity to change keys; there is no administrator recovery or classical-only escape hatch.

Program IDs in this repository are development identifiers, not proof of deployment. Upgrade authority is a separate Solana control plane and must be secured or removed before real custody. This implementation and its upstream Falcon verifier require independent review before holding valuable assets. See the implementation notes for runtime differences and test results.
