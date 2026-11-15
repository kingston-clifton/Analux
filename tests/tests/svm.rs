#![cfg(feature = "svm-tests")]
//! These tests execute the actual .so in LiteSVM, including SPL token CPIs and
//! the Ed25519 precompile. No RPC, wallet files, or network transactions are used.
use analux::{
    constants::*,
    crypto::*,
    state::{TransferIntent, Vault},
};
use analux_tests::{compute_budget, protected_transfer, upload_instructions};
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use litesvm::{
    types::{TransactionMetadata, TransactionResult},
    LiteSVM,
};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use solana_sdk::{
    clock::Clock,
    hash::Hash,
    instruction::Instruction,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    slot_hashes::SlotHashes,
    transaction::Transaction,
};

fn falcon_sign(message: &[u8], sk: &falcon512::SecretKey) -> Vec<u8> {
    for _ in 0..32 {
        let sig = falcon512::detached_sign(message, sk);
        if sig.as_bytes().len() <= SIGNATURE_LEN {
            let mut bytes = sig.as_bytes().to_vec();
            bytes.resize(SIGNATURE_LEN, 0);
            return bytes;
        }
    }
    panic!("compressed signature length rejection sampling failed")
}

fn send(svm: &mut LiteSVM, payer: &Keypair, instructions: &[Instruction]) -> TransactionResult {
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    assert!(
        bincode::serialize(&tx).unwrap().len() <= 1232,
        "legacy packet limit exceeded"
    );
    svm.send_transaction(tx)
}
fn success(result: TransactionResult) -> TransactionMetadata {
    match result {
        Ok(meta) => meta,
        Err(failure) => panic!("{:?}\n{}", failure.err, failure.meta.pretty_logs()),
    }
}
fn upload(svm: &mut LiteSVM, payer: &Keypair, bytes: &[u8]) -> Pubkey {
    let (key, ixs) = upload_instructions(payer.pubkey(), bytes);
    for ix in ixs {
        success(send(svm, payer, &[ix]));
    }
    key
}
fn read_vault(svm: &LiteSVM, address: Pubkey) -> Vault {
    let a = svm.get_account(&address).unwrap();
    Vault::try_deserialize(&mut a.data.as_slice()).unwrap()
}
fn tokens(svm: &LiteSVM, address: Pubkey) -> u64 {
    anchor_spl::token::spl_token::state::Account::unpack(&svm.get_account(&address).unwrap().data)
        .unwrap()
        .amount
}

struct Fixture {
    svm: LiteSVM,
    owner: Keypair,
    sk: falcon512::SecretKey,
    vault: Pubkey,
    source: Pubkey,
    destination: Pubkey,
}
impl Fixture {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let so = std::env::var("ANALUX_PROGRAM_SO").unwrap_or_else(|_| {
            concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/analux.so").into()
        });
        svm.add_program_from_file(analux::ID, so)
            .expect("Build the SBF program before enabling svm-tests");
        let owner = Keypair::new();
        success(svm.airdrop(&owner.pubkey(), 10_000_000_000));
        let asset_id = digest(&[b"analux svm asset"]);
        let mint = Pubkey::find_program_address(&[MINT_SEED, &asset_id], &analux::ID).0;
        let destination =
            anchor_spl::associated_token::get_associated_token_address(&owner.pubkey(), &mint);
        let mut ix = vec![compute_budget(600_000, 0)[0].clone()];
        ix.push(Instruction {
            program_id: analux::ID,
            accounts: analux::accounts::CreateAsset {
                creator: owner.pubkey(),
                mint,
                initial_tokens: destination,
                token_program: anchor_spl::token::ID,
                associated_token_program: anchor_spl::associated_token::ID,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
            data: analux::instruction::CreateAsset {
                asset_id,
                decimals: 6,
                supply: 1_000,
            }
            .data(),
        });
        success(send(&mut svm, &owner, &ix));
        let m = anchor_spl::token::spl_token::state::Mint::unpack(
            &svm.get_account(&mint).unwrap().data,
        )
        .unwrap();
        assert!(m.mint_authority.is_none() && m.freeze_authority.is_none());
        let (pk, sk) = falcon512::keypair();
        let key_hash = digest(&[pk.as_bytes()]);
        let vault = Pubkey::find_program_address(&[VAULT_SEED, &key_hash], &analux::ID).0;
        assert!(!vault.is_on_curve());
        let key_upload = upload(&mut svm, &owner, pk.as_bytes());
        let domain = digest(&[b"analux-localnet-fixture"]);
        let challenge = enrollment_digest(
            &analux::ID,
            &vault,
            &owner.pubkey(),
            &mint,
            &key_hash,
            &domain,
        );
        let enrollment_proof = upload(&mut svm, &owner, &falcon_sign(&challenge, &sk));
        let ix = Instruction {
            program_id: analux::ID,
            accounts: analux::accounts::EnrollVault {
                payer: owner.pubkey(),
                ed25519_owner: owner.pubkey(),
                key_upload,
                enrollment_proof,
                mint,
                vault,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
            data: analux::instruction::EnrollVault {
                key_hash,
                deployment_domain: domain,
            }
            .data(),
        };
        let meta = success(send(
            &mut svm,
            &owner,
            &[compute_budget(600_000, 0)[0].clone(), ix],
        ));
        println!("enrollment CU: {}", meta.compute_units_consumed);
        let source = anchor_spl::associated_token::get_associated_token_address(&vault, &mint);
        let open = Instruction {
            program_id: analux::ID,
            accounts: analux::accounts::OpenCustodyAccount {
                payer: owner.pubkey(),
                vault,
                mint,
                vault_tokens: source,
                token_program: anchor_spl::token::ID,
                associated_token_program: anchor_spl::associated_token::ID,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
            data: analux::instruction::OpenCustodyAccount {}.data(),
        };
        success(send(&mut svm, &owner, &[open.clone()]));
        success(send(&mut svm, &owner, &[open]));
        let deposit = Instruction {
            program_id: analux::ID,
            accounts: analux::accounts::Deposit {
                depositor: owner.pubkey(),
                vault,
                mint,
                source: destination,
                vault_tokens: source,
                token_program: anchor_spl::token::ID,
            }
            .to_account_metas(None),
            data: analux::instruction::Deposit { amount: 600 }.data(),
        };
        success(send(&mut svm, &owner, &[deposit]));
        svm.set_sysvar(&Clock {
            slot: 100,
            ..svm.get_sysvar::<Clock>()
        });
        svm.set_sysvar(&SlotHashes::new(&[(99, Hash::new_from_array([3; 32]))]));
        Self {
            svm,
            owner,
            sk,
            vault,
            source,
            destination,
        }
    }
    fn authorization(&mut self, amount: u64) -> (TransferIntent, [u8; 64], Pubkey) {
        let v = read_vault(&self.svm, self.vault);
        let intent = TransferIntent {
            amount,
            nonce: v.next_nonce,
            anchor_slot: 99,
            anchor_hash: [3; 32],
            valid_until_slot: 149,
        };
        let hash = intent_digest(
            &analux::ID,
            &self.vault,
            &v,
            &self.source,
            &self.destination,
            &self.owner.pubkey(),
            &intent,
        );
        let ed = ed25519_dalek::SigningKey::from_keypair_bytes(&self.owner.to_bytes()).unwrap();
        let signature = ed25519_dalek::Signer::sign(&ed, &hash).to_bytes();
        let stitched = stitched_digest(&hash, &signature, &intent);
        let upload = upload(
            &mut self.svm,
            &self.owner,
            &falcon_sign(&stitched, &self.sk),
        );
        (intent, signature, upload)
    }
    fn transfer(
        &mut self,
        intent: TransferIntent,
        signature: [u8; 64],
        upload: Pubkey,
    ) -> Vec<Instruction> {
        protected_transfer(
            self.owner.pubkey(),
            self.vault,
            &read_vault(&self.svm, self.vault),
            self.destination,
            upload,
            intent,
            signature,
            500_000,
        )
    }
    fn assert_unchanged(&self) {
        assert_eq!(tokens(&self.svm, self.source), 600);
        assert_eq!(tokens(&self.svm, self.destination), 400);
        assert_eq!(read_vault(&self.svm, self.vault).next_nonce, 0);
    }
}

#[test]
fn full_sbf_custody_transfer_nonce_and_rent_lifecycle() {
    let mut f = Fixture::new();
    let (intent, ed, proof) = f.authorization(123);
    let ixs = f.transfer(intent, ed, proof);
    let meta = success(send(&mut f.svm, &f.owner, &ixs));
    println!("protected transfer CU: {}", meta.compute_units_consumed);
    assert_eq!(tokens(&f.svm, f.source), 477);
    assert_eq!(tokens(&f.svm, f.destination), 523);
    assert_eq!(read_vault(&f.svm, f.vault).next_nonce, 1);
    let failed = send(&mut f.svm, &f.owner, &ixs).unwrap_err();
    assert!(failed.meta.logs.iter().any(|x| x.contains("InvalidNonce")));
    let close = Instruction {
        program_id: analux::ID,
        accounts: analux::accounts::CloseUpload {
            uploader: f.owner.pubkey(),
            upload: proof,
        }
        .to_account_metas(None),
        data: analux::instruction::CloseUpload {}.data(),
    };
    success(send(&mut f.svm, &f.owner, &[close]));
    assert!(f.svm.get_account(&proof).is_none_or(|a| a.lamports == 0));
}

#[test]
fn valid_classical_signature_cannot_rescue_tampered_falcon_intent() {
    let mut f = Fixture::new();
    let (mut intent, _, proof) = f.authorization(123);
    intent.amount = 599;
    let v = read_vault(&f.svm, f.vault);
    let h = intent_digest(
        &analux::ID,
        &f.vault,
        &v,
        &f.source,
        &f.destination,
        &f.owner.pubkey(),
        &intent,
    );
    let ed = ed25519_dalek::SigningKey::from_keypair_bytes(&f.owner.to_bytes()).unwrap();
    let sig = ed25519_dalek::Signer::sign(&ed, &h).to_bytes();
    let ixs = f.transfer(intent, sig, proof);
    let failure = send(&mut f.svm, &f.owner, &ixs).unwrap_err();
    assert!(failure
        .meta
        .logs
        .iter()
        .any(|x| x.contains("InvalidFalconSignature")));
    f.assert_unchanged();
}

#[test]
fn dqip_expiry_substitution_and_extra_instructions_fail_closed() {
    let mut f = Fixture::new();
    let (intent, ed, proof) = f.authorization(123);
    let ixs = f.transfer(intent.clone(), ed, proof);
    let mut cheap = ixs.clone();
    cheap[1] = compute_budget(500_000, 1)[1].clone();
    let failed = send(&mut f.svm, &f.owner, &cheap).unwrap_err();
    assert!(failed
        .meta
        .logs
        .iter()
        .any(|x| x.contains("InsufficientPriorityFee")));
    f.assert_unchanged();
    let mut extra = ixs.clone();
    extra.push(solana_sdk::system_instruction::transfer(
        &f.owner.pubkey(),
        &Pubkey::new_unique(),
        1,
    ));
    let failed = send(&mut f.svm, &f.owner, &extra).unwrap_err();
    assert!(failed
        .meta
        .logs
        .iter()
        .any(|x| x.contains("InvalidTransactionShape")));
    f.assert_unchanged();
    let mut swapped = ixs.clone();
    swapped[3].accounts[4].pubkey = f.source;
    assert!(send(&mut f.svm, &f.owner, &swapped).is_err());
    f.assert_unchanged();
    f.svm.set_sysvar(&Clock {
        slot: 200,
        ..f.svm.get_sysvar::<Clock>()
    });
    let failed = send(&mut f.svm, &f.owner, &ixs).unwrap_err();
    assert!(failed
        .meta
        .logs
        .iter()
        .any(|x| x.contains("ExpiredAuthorization")));
    f.assert_unchanged();
}

#[test]
fn buffer_mutation_foreign_uploader_and_signature_only_bypass_are_rejected() {
    let mut f = Fixture::new();
    let (intent, ed, proof) = f.authorization(123);
    let overwrite = Instruction {
        program_id: analux::ID,
        accounts: analux::accounts::EditUpload {
            uploader: f.owner.pubkey(),
            upload: proof,
        }
        .to_account_metas(None),
        data: analux::instruction::AppendUpload {
            offset: 0,
            bytes: vec![0; 10],
        }
        .data(),
    };
    let failure = send(&mut f.svm, &f.owner, &[overwrite]).unwrap_err();
    assert!(failure
        .meta
        .logs
        .iter()
        .any(|x| x.contains("InvalidUpload")));
    let foreign = Keypair::new();
    success(f.svm.airdrop(&foreign.pubkey(), 5_000_000));
    let foreign_close = Instruction {
        program_id: analux::ID,
        accounts: analux::accounts::CloseUpload {
            uploader: foreign.pubkey(),
            upload: proof,
        }
        .to_account_metas(None),
        data: analux::instruction::CloseUpload {}.data(),
    };
    assert!(send(&mut f.svm, &foreign, &[foreign_close]).is_err());
    assert!(f.svm.get_account(&proof).is_some());
    let mut only_classical = f.transfer(intent, ed, proof);
    only_classical.remove(2);
    assert!(send(&mut f.svm, &f.owner, &only_classical).is_err());
    f.assert_unchanged();
}

#[test]
fn failed_spl_cpi_rolls_back_the_consumed_nonce() {
    let mut f = Fixture::new();
    let (intent, ed, proof) = f.authorization(601); // Only 600 tokens are in custody.
    let ixs = f.transfer(intent, ed, proof);
    let failure = send(&mut f.svm, &f.owner, &ixs).unwrap_err();
    assert!(failure
        .meta
        .logs
        .iter()
        .any(|x| x.contains("insufficient funds")));
    f.assert_unchanged();
}
