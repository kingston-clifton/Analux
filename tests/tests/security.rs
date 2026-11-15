use analux::{
    constants::*,
    crypto::*,
    guards::*,
    state::{TransferIntent, Upload, Vault},
};
use analux_tests::compute_budget;
use anchor_lang::prelude::Pubkey;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

// Ephemeral synthetic test credentials only. No private keys leave this process.
fn sign(message: &[u8], sk: &falcon512::SecretKey) -> Vec<u8> {
    for _ in 0..32 {
        let sig = falcon512::detached_sign(message, sk);
        if sig.as_bytes().len() <= SIGNATURE_LEN {
            let mut out = sig.as_bytes().to_vec();
            out.resize(SIGNATURE_LEN, 0);
            return out;
        }
    }
    panic!("Unable to sample a compressed signature fitting the 666-byte protocol limit");
}

fn vault() -> Vault {
    Vault {
        version: VERSION,
        bump: 255,
        ed25519_owner: Pubkey::new_unique(),
        mint: Pubkey::new_unique(),
        key_hash: [1; 32],
        deployment_domain: [2; 32],
        next_nonce: 0,
        raw_key: vec![],
        prepared_key: vec![],
    }
}
fn intent() -> TransferIntent {
    TransferIntent {
        amount: 100,
        nonce: 0,
        anchor_slot: 50,
        anchor_hash: [3; 32],
        valid_until_slot: 150,
    }
}

#[test]
fn real_falcon_signatures_and_wrong_keys_are_distinguished() {
    let (pk, sk) = falcon512::keypair();
    let (wrong_pk, _) = falcon512::keypair();
    let message = digest(&[b"actual Falcon verification"]);
    let sig = sign(&message, &sk);
    falcon512::verify_detached_signature(
        &falcon512::DetachedSignature::from_bytes(&sig).unwrap(),
        &message,
        &pk,
    )
    .unwrap();
    let prepared = prepare_key(pk.as_bytes()).unwrap();
    verify_falcon(&prepared, &sig, &message).unwrap();
    let mut unaligned = vec![0];
    unaligned.extend_from_slice(&prepared);
    verify_falcon(&unaligned[1..], &sig, &message).unwrap();
    let mut invalid_coefficients = prepared.clone();
    invalid_coefficients[..2].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(verify_falcon(&invalid_coefficients, &sig, &message).is_err());
    assert!(verify_falcon(&prepare_key(wrong_pk.as_bytes()).unwrap(), &sig, &message).is_err());
    assert!(verify_falcon(&prepared, &sig, &digest(&[b"tampered"])).is_err());
    let mut tampered = sig.clone();
    tampered[80] ^= 1;
    assert!(verify_falcon(&prepared, &tampered, &message).is_err());
    assert!(verify_falcon(&prepared, &sig[..665], &message).is_err());
    assert!(prepare_key(&vec![0; KEY_LEN]).is_err());
}

#[test]
fn every_transfer_field_account_and_program_is_bound() {
    let v = vault();
    let a = Pubkey::new_unique();
    let s = Pubkey::new_unique();
    let d = Pubkey::new_unique();
    let p = Pubkey::new_unique();
    let t = intent();
    let original = intent_digest(&analux::ID, &a, &v, &s, &d, &p, &t);
    let mut changes = vec![];
    for field in 0..5 {
        let mut x = t.clone();
        match field {
            0 => x.amount += 1,
            1 => x.nonce += 1,
            2 => x.anchor_slot += 1,
            3 => x.anchor_hash[0] ^= 1,
            _ => x.valid_until_slot += 1,
        };
        changes.push(intent_digest(&analux::ID, &a, &v, &s, &d, &p, &x));
    }
    for field in 0..5 {
        let x = Pubkey::new_unique();
        changes.push(match field {
            0 => intent_digest(&x, &a, &v, &s, &d, &p, &t),
            1 => intent_digest(&analux::ID, &x, &v, &s, &d, &p, &t),
            2 => intent_digest(&analux::ID, &a, &v, &x, &d, &p, &t),
            3 => intent_digest(&analux::ID, &a, &v, &s, &x, &p, &t),
            _ => intent_digest(&analux::ID, &a, &v, &s, &d, &x, &t),
        });
    }
    for field in 0..4 {
        let mut x = vault();
        x.ed25519_owner = v.ed25519_owner;
        x.mint = v.mint;
        match field {
            0 => x.ed25519_owner = Pubkey::new_unique(),
            1 => x.mint = Pubkey::new_unique(),
            2 => x.key_hash[0] ^= 1,
            _ => x.deployment_domain[0] ^= 1,
        };
        changes.push(intent_digest(&analux::ID, &a, &x, &s, &d, &p, &t));
    }
    assert!(changes.iter().all(|x| *x != original));
    assert_ne!(
        stitched_digest(&original, &[7; 64], &t),
        stitched_digest(&original, &[8; 64], &t)
    );
}

#[test]
fn enrollment_proof_cannot_be_rebound_to_another_identity() {
    let (pk, sk) = falcon512::keypair();
    let key_hash = digest(&[pk.as_bytes()]);
    let a = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let domain = [8; 32];
    let challenge = enrollment_digest(&analux::ID, &a, &owner, &mint, &key_hash, &domain);
    let sig = sign(&challenge, &sk);
    let prepared = prepare_key(pk.as_bytes()).unwrap();
    verify_falcon(&prepared, &sig, &challenge).unwrap();
    let substituted = enrollment_digest(
        &analux::ID,
        &a,
        &Pubkey::new_unique(),
        &mint,
        &key_hash,
        &domain,
    );
    assert!(verify_falcon(&prepared, &sig, &substituted).is_err());
}

#[test]
fn ed25519_instruction_requires_exact_local_offsets_and_message() {
    let owner = Pubkey::new_unique();
    let sig = [3; 64];
    let message = [4; 32];
    let ix = ed25519_instruction(&owner, &sig, &message);
    validate_ed25519(&ix, &owner, &sig, &message).unwrap();
    for index in [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 80, 112] {
        let mut bad = ix.clone();
        bad.data[index] ^= 1;
        assert!(validate_ed25519(&bad, &owner, &sig, &message).is_err());
    }
    let mut bad = ix;
    bad.program_id = Pubkey::new_unique();
    assert!(validate_ed25519(&bad, &owner, &sig, &message).is_err());
}

#[test]
fn dqip_uses_requested_units_rounds_up_and_cannot_overflow() {
    let [limit, price] = compute_budget(400_000, 2_500_000);
    assert_eq!(priority_fee(&limit, &price).unwrap(), DQIP_LAMPORTS);
    let [limit, price] = compute_budget(3, 333_334);
    assert_eq!(priority_fee(&limit, &price).unwrap(), 2);
    let [limit, price] = compute_budget(1_400_001, 1);
    assert!(priority_fee(&limit, &price).is_err());
    let [limit, price] = compute_budget(1_400_000, u64::MAX);
    assert!(priority_fee(&limit, &price).is_err());
}

#[test]
fn temporal_anchor_is_checked_against_authenticated_history() {
    let t = intent();
    let mut data = 1u64.to_le_bytes().to_vec();
    data.extend_from_slice(&t.anchor_slot.to_le_bytes());
    data.extend_from_slice(&t.anchor_hash);
    validate_anchor(&data, 75, &t).unwrap();
    assert!(validate_anchor(&data, 151, &t).is_err());
    assert!(validate_anchor(&data, 49, &t).is_err());
    let mut changed = t.clone();
    changed.anchor_hash[0] ^= 1;
    assert!(validate_anchor(&data, 75, &changed).is_err());
    changed = t.clone();
    changed.valid_until_slot = 999;
    assert!(validate_anchor(&data, 75, &changed).is_err());
    assert!(validate_anchor(&data[..20], 75, &t).is_err());
}

#[test]
fn incomplete_or_modified_uploads_are_rejected() {
    let bytes = vec![9; KEY_LEN];
    let mut u = Upload {
        uploader: Pubkey::new_unique(),
        object_hash: digest(&[&bytes]),
        expected_len: KEY_LEN as u16,
        bytes,
    };
    complete_upload(&u, KEY_LEN).unwrap();
    u.bytes[0] ^= 1;
    assert!(complete_upload(&u, KEY_LEN).is_err());
    u.bytes.pop();
    assert!(complete_upload(&u, KEY_LEN).is_err());
}
