#![cfg_attr(not(feature = "std"), no_std)]

use parity_scale_codec::{Decode, Encode};
use sc_consensus_pow::PowAlgorithm;
use sp_consensus_pow::Seal;
use sp_core::U256;
use sp_runtime::traits::Block as BlockT;

/// A tiny PoW that uses a 64-bit checksum(work) over (pre_hash || nonce).
/// Work succeeds when work < target.  For demo/dev only.
#[derive(Clone)]
pub struct MiniPow;

#[derive(Encode, Decode, Clone, Copy, Debug)]
pub struct Nonce(u64);

impl Nonce {
    pub fn to_seal(self) -> Seal {
        self.0.to_le_bytes().to_vec()
    }
    pub fn from_seal(seal: &Seal) -> Option<Self> {
        if seal.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&seal[..8]);
            Some(Nonce(u64::from_le_bytes(b)))
        } else {
            None
        }
    }
}

/// Sum of bytes mod 2^64 over pre_hash || nonce_le
fn checksum64<B: BlockT>(pre_hash: &B::Hash, nonce: u64) -> u64 {
    let mut acc: u64 = 0;
    // Hash is typically 32 bytes (H256) – treat generically:
    for byte in pre_hash.as_ref() {
        acc = acc.wrapping_add(*byte as u64);
    }
    for byte in nonce.to_le_bytes() {
        acc = acc.wrapping_add(byte as u64);
    }
    acc
}

/// Convert U256 target into a 64-bit threshold by clamping.
/// This keeps compatibility with PoW difficulty APIs while our work is 64-bit.
fn target64(target: &U256) -> u64 {
    // Take low 64 bits; if target doesn't fit, we saturate to u64::MAX.
    if *target > U256::from(u64::MAX) {
        u64::MAX
    } else {
        target.low_u64()
    }
}

impl<B> PowAlgorithm<B> for MiniPow
where
    B: BlockT,
{
    type Difficulty = U256;

    fn difficulty(&self, _parent: &sp_runtime::generic::BlockId<B>) -> Result<Self::Difficulty, sp_blockchain::Error> {
        // Minimal fixed difficulty for dev chains. Tweak as desired.
        // Higher target => easier. Start permissive to avoid long mining.
        Ok(U256::from(u64::MAX / 1024)) // easy target
    }

    fn verify(
        &self,
        pre_hash: &B::Hash,
        seal: &Seal,
        target: &Self::Difficulty,
    ) -> bool {
        let Some(Nonce(n)) = Nonce::from_seal(seal) else { return false; };
        let work = checksum64::<B>(pre_hash, n);
        work < target64(target)
    }

    fn mine(
        &self,
        pre_hash: &B::Hash,
        target: &Self::Difficulty,
        mut round: u32,
    ) -> Option<Seal> {
        // Deterministic, round-based search. Each call advances nonce window.
        // This is single-threaded & intentionally dumb.
        let t = target64(target);
        let base: u64 = (round as u64) << 32;
        let limit: u64 = base + (1u64 << 20); // search 1M candidates per round
        let mut nonce = base;
        while nonce < limit {
            if checksum64::<B>(pre_hash, nonce) < t {
                return Some(Nonce(nonce).to_seal());
            }
            nonce = nonce.wrapping_add(1);
        }
        // No solution in this slice; bump round and try later.
        round = round.wrapping_add(1);
        None
    }
}
