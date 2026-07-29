// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom as _;

use crate::{
    Error, Res,
    err::IntoResult as _,
    init,
    p11::{
        self, Context, PK11_CreateDigestContext, PK11_DigestBegin, PK11_DigestFinal, PK11_DigestOp,
        PK11_HashBuf, SECOidTag,
    },
};

//
// Constants
//

#[derive(Clone, Copy)]
pub enum HashAlgorithm {
    SHA2_256,
    SHA2_384,
    SHA2_512,
}

const fn hash_alg_to_oid(alg: HashAlgorithm) -> SECOidTag::Type {
    match alg {
        HashAlgorithm::SHA2_256 => SECOidTag::SEC_OID_SHA256,
        HashAlgorithm::SHA2_384 => SECOidTag::SEC_OID_SHA384,
        HashAlgorithm::SHA2_512 => SECOidTag::SEC_OID_SHA512,
    }
}

#[must_use]
pub const fn hash_alg_to_hash_len(alg: &HashAlgorithm) -> usize {
    match alg {
        HashAlgorithm::SHA2_256 => p11::SHA256_LENGTH as usize,
        HashAlgorithm::SHA2_384 => p11::SHA384_LENGTH as usize,
        HashAlgorithm::SHA2_512 => p11::SHA512_LENGTH as usize,
    }
}

//
// Hash function
//

pub fn hash(alg: &HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
    init()?;

    let data_len: i32 = match i32::try_from(data.len()) {
        Ok(data_len) => data_len,
        _ => return Err(Error::Internal),
    };
    let expected_len = hash_alg_to_hash_len(alg);
    let mut digest = vec![0u8; expected_len];
    unsafe {
        PK11_HashBuf(
            hash_alg_to_oid(*alg),
            digest.as_mut_ptr(),
            data.as_ptr(),
            data_len,
        )
        .into_result()?;
    };
    Ok(digest)
}

/// Incremental data hasher (`PK11_DigestContext` wrapper).
///
/// This allows hashing data without needing it all in memory at once.
///
/// # Example
///
/// ```rust
/// # fn main() -> nss_rs::Res<()> {
/// use nss_rs::hash::{DigestContext, HashAlgorithm};
/// let mut c = DigestContext::new(HashAlgorithm::SHA2_256)?;
///
/// // Now hash data in chunks. You could read it from a file or stream.
/// for _ in 0..1024 {
///     c.update(&[0; 1024])?;
/// }
///
/// assert_eq!(
///     c.digest()?.as_slice(),
///     &[
///         48, 225, 73, 85, 235, 241, 53, 34, 102, 220, 47, 248, 6, 126, 104, 16, 70, 7, 231,
///         80, 171, 185, 211, 179, 101, 130, 184, 175, 144, 159, 203, 88
///     ]
/// );
/// # Ok(())
/// # }
/// ```
pub struct DigestContext {
    context: Context,
    alg: HashAlgorithm,
}

impl DigestContext {
    /// Create a new digest context (`PK11_CreateDigestContext`).
    pub fn new(alg: HashAlgorithm) -> Res<Self> {
        init()?;

        let context = unsafe { PK11_CreateDigestContext(hash_alg_to_oid(alg)) }.into_result()?;
        unsafe { PK11_DigestBegin(*context) }.into_result()?;

        Ok(Self { context, alg })
    }

    /// Add data to the digest context.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let data_len = u32::try_from(data.len()).map_err(|_| Error::IntegerOverflow)?;
        unsafe { PK11_DigestOp(*self.context, data.as_ptr(), data_len) }.into_result()
    }

    /// Finalize the digest context, returning a digest hash.
    pub fn digest(&self) -> Res<Vec<u8>> {
        let expected_len = self.digest_size();
        let mut digest = vec![0u8; expected_len];
        let mut len = u32::try_from(expected_len).map_err(|_| Error::IntegerOverflow)?;

        unsafe { PK11_DigestFinal(*self.context, digest.as_mut_ptr(), &raw mut len, len) }
            .into_result()?;

        Ok(digest)
    }

    /// Size of the resulting hash, in bytes.
    #[must_use]
    pub const fn digest_size(&self) -> usize {
        hash_alg_to_hash_len(&self.alg)
    }
}
