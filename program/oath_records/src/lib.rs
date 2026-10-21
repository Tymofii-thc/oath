//! oath_records: one on-chain account per (signer, digest), looked up directly by address.
//!
//! This complements (does not replace) the Memo-based "v1" records the rest of oath uses. The Memo
//! model requires paging back through a signer's transaction history (`getSignaturesForAddress`,
//! bounded by `--limit`), so an attacker who spams a signer's address with enough transactions can
//! push an old revocation out of the scanned window and make a revoked digest verify again
//! (see THREAT-MODEL.md, "Spam a signer's address..."). A program-derived account has no window to
//! evict from: it is looked up by its deterministic address in a single `getAccountInfo` call, and
//! either exists or does not, permanently, with no instruction in this program to delete it.
//!
//! Two instructions, each idempotent (a repeat call is a cheap success, not an error, so a CI retry
//! or re-deploy doesn't fail):
//!   0 Record(digest, image_hash, commit, ts) -> creates/confirms a PDA at seeds [b"oath1rec", signer, digest]
//!   1 Revoke(digest, reason, ts)             -> creates/confirms a PDA at seeds [b"oath1rev", signer, digest]
//!
//! Verification (done off-chain, in lib/pda.mjs) loops the trusted signer list exactly as the Memo
//! path does: for each signer, check its revoke PDA first (final, like the existing policy), else its
//! record PDA. No instruction here ever closes an account, so "final" is enforced by the program, not
//! by client-side policy alone.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::instruction as system_instruction;

entrypoint!(process_instruction);

pub const RECORD_SEED: &[u8] = b"oath1rec";
pub const REVOKE_SEED: &[u8] = b"oath1rev";

pub const RECORD_LEN: usize = 1 + 1 + 32 + 32 + 32 + 12 + 8; // tag, bump, signer, digest, image_hash, commit, ts
pub const REVOKE_LEN: usize = 1 + 1 + 32 + 32 + 64 + 8; // tag, bump, signer, digest, reason, ts

const TAG_RECORD: u8 = 1;
const TAG_REVOKE: u8 = 2;

fn invalid(msg: &str) -> ProgramError {
    solana_program::msg!("oath_records: {}", msg);
    ProgramError::InvalidInstructionData
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&tag, rest) = data.split_first().ok_or_else(|| invalid("empty instruction data"))?;
    match tag {
        0 => process_record(program_id, accounts, rest),
        1 => process_revoke(program_id, accounts, rest),
        _ => Err(invalid("unknown instruction tag")),
    }
}

/// Creates the PDA account, also when someone sent lamports to the address first.
///
/// Anyone can transfer lamports to any address without its signature, so a plain `create_account` (which fails
/// on an address that already holds lamports) would let a third party block a record, or worse a revocation,
/// forever by pre-funding the PDA (found in review, reproduced on devnet). The account is then topped up to the
/// rent-exempt minimum, given its size and assigned to this program instead. The PDA signs for allocate/assign
/// through its seeds, which only this program can do.
fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    program_id: &Pubkey,
    space: usize,
    seeds: &[&[u8]],
) -> ProgramResult {
    let rent = Rent::get()?.minimum_balance(space);
    let have = pda.lamports();
    if have == 0 {
        return invoke_signed(
            &system_instruction::create_account(payer.key, pda.key, rent, space as u64, program_id),
            &[payer.clone(), pda.clone(), system.clone()],
            &[seeds],
        );
    }
    if have < rent {
        invoke(
            &system_instruction::transfer(payer.key, pda.key, rent - have),
            &[payer.clone(), pda.clone(), system.clone()],
        )?;
    }
    invoke_signed(&system_instruction::allocate(pda.key, space as u64), &[pda.clone(), system.clone()], &[seeds])?;
    invoke_signed(&system_instruction::assign(pda.key, program_id), &[pda.clone(), system.clone()], &[seeds])
}

fn process_record(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 32 + 32 + 12 + 8 {
        return Err(invalid("Record: bad instruction data length"));
    }
    let digest: [u8; 32] = data[0..32].try_into().unwrap();
    let image_hash: [u8; 32] = data[32..64].try_into().unwrap();
    let commit: [u8; 12] = data[64..76].try_into().unwrap();
    let ts = i64::from_le_bytes(data[76..84].try_into().unwrap());

    let iter = &mut accounts.iter();
    let signer = next_account_info(iter)?;
    let record = next_account_info(iter)?;
    let system = next_account_info(iter)?;

    if !signer.is_signer {
        return Err(invalid("Record: signer did not sign"));
    }

    let (expected, bump) = Pubkey::find_program_address(&[RECORD_SEED, signer.key.as_ref(), &digest], program_id);
    if expected != *record.key {
        return Err(invalid("Record: PDA address does not match the given seeds"));
    }

    if record.owner == program_id {
        // Already anchored by this signer for this digest: idempotent success, no rewrite.
        // (A record is a historical fact; it does not change once it exists.)
        return Ok(());
    }
    // a system-owned, data-less account (empty, or pre-funded by anyone) is fine; anything else is not ours
    if record.owner != system.key || !record.data_is_empty() {
        return Err(invalid("Record: PDA account exists but is not ours"));
    }

    let seeds: &[&[u8]] = &[RECORD_SEED, signer.key.as_ref(), &digest, &[bump]];
    create_pda_account(signer, record, system, program_id, RECORD_LEN, seeds)?;

    let mut out = record.try_borrow_mut_data()?;
    out[0] = TAG_RECORD;
    out[1] = bump;
    out[2..34].copy_from_slice(signer.key.as_ref());
    out[34..66].copy_from_slice(&digest);
    out[66..98].copy_from_slice(&image_hash);
    out[98..110].copy_from_slice(&commit);
    out[110..118].copy_from_slice(&ts.to_le_bytes());
    Ok(())
}

fn process_revoke(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 32 + 64 + 8 {
        return Err(invalid("Revoke: bad instruction data length"));
    }
    let digest: [u8; 32] = data[0..32].try_into().unwrap();
    let reason: [u8; 64] = data[32..96].try_into().unwrap();
    let ts = i64::from_le_bytes(data[96..104].try_into().unwrap());

    let iter = &mut accounts.iter();
    let signer = next_account_info(iter)?;
    let revoke = next_account_info(iter)?;
    let system = next_account_info(iter)?;

    if !signer.is_signer {
        return Err(invalid("Revoke: signer did not sign"));
    }

    let (expected, bump) = Pubkey::find_program_address(&[REVOKE_SEED, signer.key.as_ref(), &digest], program_id);
    if expected != *revoke.key {
        return Err(invalid("Revoke: PDA address does not match the given seeds"));
    }

    if revoke.owner == program_id {
        // A revocation is final: once it exists, this program never overwrites or removes it.
        return Ok(());
    }
    if revoke.owner != system.key || !revoke.data_is_empty() {
        return Err(invalid("Revoke: PDA account exists but is not ours"));
    }

    let seeds: &[&[u8]] = &[REVOKE_SEED, signer.key.as_ref(), &digest, &[bump]];
    create_pda_account(signer, revoke, system, program_id, REVOKE_LEN, seeds)?;

    let mut out = revoke.try_borrow_mut_data()?;
    out[0] = TAG_REVOKE;
    out[1] = bump;
    out[2..34].copy_from_slice(signer.key.as_ref());
    out[34..66].copy_from_slice(&digest);
    out[66..130].copy_from_slice(&reason);
    out[130..138].copy_from_slice(&ts.to_le_bytes());
    Ok(())
}
