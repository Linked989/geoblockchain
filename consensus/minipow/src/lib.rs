#![cfg_attr(not(feature = "std"), no_std)]

use parity_scale_codec::{Decode, Encode};
use sc_consensus_pow::{PowAlgorithm, Error as PowError};
use sp_consensus_pow::Seal as RawSeal;
use sp_core::U256;
use sp_runtime::{traits::Block as BlockT, generic::BlockId};

/// A tiny PoW that uses a 64-bit checksum over (pre_hash || nonce).
/// Work succeeds when sum(bytes) < target. Dev/demo only.
#[derive(Clone)]
pub struct MiniPow;

#[derive(Encode, Decode, Clone, Copy, Debug)]
pub struct Nonce(u64);

impl Nonce {
    pub fn to_seal(self) -> RawSeal {
        self.0.to_le_bytes().to_vec()
    }
    pub fn from_seal(seal: &RawSeal) -> Option<Self> {
        if seal.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&seal[..8]);
            Some(Nonce(u64::from_le_bytes(b)))
        } else {
            None
        }
    }
}

fn checksum64<B: BlockT>(pre_hash: &B::Hash, nonce: u64) -> u64 {
    let mut acc: u64 = 0;
    for byte in pre_hash.as_ref() {
        acc = acc.wrapping_add(*byte as u64);
    }
    for byte in nonce.to_le_bytes() {
        acc = acc.wrapping_add(byte as u64);
    }
    acc
}

fn target64(target: &U256) -> u64 {
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

    /// Return the current target (easy for dev).
    fn difficulty(
        &self,
        _parent: B::Hash,
    ) -> Result<Self::Difficulty, PowError<B>> {
        // Very permissive by default: u64::MAX/1024 as a U256.
        Ok(U256::from(u64::MAX / 1024))
    }

    /// Verify a seal: (parent, pre_hash, digest, seal, target)
    fn verify(
        &self,
        _parent: &BlockId<B>,
        pre_hash: &B::Hash,
        _digest: Option<&[u8]>,
        seal: &RawSeal,
        target: &Self::Difficulty,
    ) -> Result<bool, PowError<B>> {
        // If the seal cannot be parsed, consider verification failed.
        let Nonce(n) = match Nonce::from_seal(seal) {
            Some(n) => n,
            None => return Ok(false),
        };
        let work = checksum64::<B>(pre_hash, n);
        Ok(work < target64(target))
    }
}
