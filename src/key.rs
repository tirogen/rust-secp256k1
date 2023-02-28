// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Public and secret keys
#[cfg(any(test, feature = "rand"))]
use rand_legacy::Rng;

use core::{fmt, str};

use super::Error::{self, InvalidPublicKey, InvalidSecretKey};
use super::{from_hex, Secp256k1};
use constants;
use ffi::{self, CPtr};
use Signing;
use Verification;

/// Secret 256-bit key used as `x` in an ECDSA signature
pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
impl_array_newtype!(SecretKey, u8, constants::SECRET_KEY_SIZE);
impl_pretty_debug!(SecretKey);

impl fmt::LowerHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in &self.0[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for SecretKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<SecretKey, Error> {
        let mut res = [0; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) => SecretKey::from_slice(&res),
            _ => Err(Error::InvalidSecretKey),
        }
    }
}

/// The number 1 encoded as a secret key
pub const ONE_KEY: SecretKey = SecretKey([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

/// A Secp256k1 public key, used for verification of signatures
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(transparent)]
pub struct PublicKey(ffi::PublicKey);

impl fmt::LowerHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        let mut res = [0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::PUBLIC_KEY_SIZE) => {
                PublicKey::from_slice(&res[0..constants::PUBLIC_KEY_SIZE])
            }
            Ok(constants::UNCOMPRESSED_PUBLIC_KEY_SIZE) => PublicKey::from_slice(&res),
            _ => Err(Error::InvalidPublicKey),
        }
    }
}

#[cfg(any(test, feature = "rand"))]
fn random_32_bytes() -> [u8; 32] {
    let mut rng = rand_legacy::thread_rng();
    let mut ret = [0u8; 32];
    rng.fill_bytes(&mut ret);
    ret
}

impl SecretKey {
    /// Creates a new random secret key. Requires compilation with the "rand" feature.
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn new() -> SecretKey {
        let mut data = random_32_bytes();
        unsafe {
            while ffi::secp256k1_ec_seckey_verify(
                ffi::secp256k1_context_no_precomp,
                data.as_c_ptr(),
            ) == 0
            {
                data = random_32_bytes();
            }
        }
        SecretKey(data)
    }

    /// Converts a `SECRET_KEY_SIZE`-byte slice to a secret key
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<SecretKey, Error> {
        match data.len() {
            constants::SECRET_KEY_SIZE => {
                let mut ret = [0; constants::SECRET_KEY_SIZE];
                unsafe {
                    if ffi::secp256k1_ec_seckey_verify(
                        ffi::secp256k1_context_no_precomp,
                        data.as_c_ptr(),
                    ) == 0
                    {
                        return Err(InvalidSecretKey);
                    }
                }
                ret[..].copy_from_slice(data);
                Ok(SecretKey(ret))
            }
            _ => Err(InvalidSecretKey),
        }
    }

    #[inline]
    /// Negates one secret key.
    pub fn negate_assign(&mut self) {
        unsafe {
            let res = ffi::secp256k1_ec_seckey_negate(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
            );
            debug_assert_eq!(res, 1);
        }
    }

    #[inline]
    /// Adds one secret key to another, modulo the curve order. WIll
    /// return an error if the resulting key would be invalid or if
    /// the tweak was not a 32-byte length slice.
    pub fn add_assign(&mut self, other: &[u8]) -> Result<(), Error> {
        if other.len() != 32 {
            return Err(Error::InvalidTweak);
        }
        unsafe {
            if ffi::secp256k1_ec_seckey_tweak_add(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                other.as_c_ptr(),
            ) != 1
            {
                Err(Error::InvalidTweak)
            } else {
                Ok(())
            }
        }
    }

    #[inline]
    /// Multiplies one secret key by another, modulo the curve order. Will
    /// return an error if the resulting key would be invalid or if
    /// the tweak was not a 32-byte length slice.
    pub fn mul_assign(&mut self, other: &[u8]) -> Result<(), Error> {
        if other.len() != 32 {
            return Err(Error::InvalidTweak);
        }
        unsafe {
            if ffi::secp256k1_ec_seckey_tweak_mul(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                other.as_c_ptr(),
            ) != 1
            {
                Err(Error::InvalidTweak)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for SecretKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for SecretKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte SecretKey",
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "raw 32 bytes SecretKey",
                SecretKey::from_slice,
            ))
        }
    }
}

impl PublicKey {
    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::PublicKey {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::PublicKey {
        &mut self.0
    }

    /// Creates a new public key from a secret key.
    #[inline]
    pub fn from_secret_key<C: Signing>(secp: &Secp256k1<C>, sk: &SecretKey) -> PublicKey {
        unsafe {
            let mut pk = ffi::PublicKey::new();
            // We can assume the return value because it's not possible to construct
            // an invalid `SecretKey` without transmute trickery or something
            let res = ffi::secp256k1_ec_pubkey_create(secp.ctx, &mut pk, sk.as_c_ptr());
            debug_assert_eq!(res, 1);
            PublicKey(pk)
        }
    }

    /// Creates a public key directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        if data.is_empty() {
            return Err(Error::InvalidPublicKey);
        }

        unsafe {
            let mut pk = ffi::PublicKey::new();
            if ffi::secp256k1_ec_pubkey_parse(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                data.as_c_ptr(),
                data.len() as usize,
            ) == 1
            {
                Ok(PublicKey(pk))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }

    #[inline]
    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    pub fn serialize(&self) -> [u8; constants::PUBLIC_KEY_SIZE] {
        let mut ret = [0; constants::PUBLIC_KEY_SIZE];

        unsafe {
            let mut ret_len = constants::PUBLIC_KEY_SIZE as usize;
            let err = ffi::secp256k1_ec_pubkey_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                &mut ret_len,
                self.as_c_ptr(),
                ffi::SECP256K1_SER_COMPRESSED,
            );
            debug_assert_eq!(err, 1);
            debug_assert_eq!(ret_len, ret.len());
        }
        ret
    }

    /// Serialize the key as a byte-encoded pair of values, in uncompressed form
    pub fn serialize_uncompressed(&self) -> [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE] {
        let mut ret = [0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];

        unsafe {
            let mut ret_len = constants::UNCOMPRESSED_PUBLIC_KEY_SIZE as usize;
            let err = ffi::secp256k1_ec_pubkey_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                &mut ret_len,
                self.as_c_ptr(),
                ffi::SECP256K1_SER_UNCOMPRESSED,
            );
            debug_assert_eq!(err, 1);
            debug_assert_eq!(ret_len, ret.len());
        }
        ret
    }

    #[inline]
    /// Negates the pk to the pk `self` in place
    /// Will return an error if the pk would be invalid.
    pub fn negate_assign<C: Verification>(&mut self, secp: &Secp256k1<C>) {
        unsafe {
            let res = ffi::secp256k1_ec_pubkey_negate(secp.ctx, &mut self.0);
            debug_assert_eq!(res, 1);
        }
    }

    #[inline]
    /// Adds the pk corresponding to `other` to the pk `self` in place
    /// Will return an error if the resulting key would be invalid or
    /// if the tweak was not a 32-byte length slice.
    pub fn add_exp_assign<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        other: &[u8],
    ) -> Result<(), Error> {
        if other.len() != 32 {
            return Err(Error::InvalidTweak);
        }
        unsafe {
            if ffi::secp256k1_ec_pubkey_tweak_add(secp.ctx, &mut self.0, other.as_c_ptr()) == 1 {
                Ok(())
            } else {
                Err(Error::InvalidTweak)
            }
        }
    }

    #[inline]
    /// Muliplies the pk `self` in place by the scalar `other`
    /// Will return an error if the resulting key would be invalid or
    /// if the tweak was not a 32-byte length slice.
    pub fn mul_assign<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        other: &[u8],
    ) -> Result<(), Error> {
        if other.len() != 32 {
            return Err(Error::InvalidTweak);
        }
        unsafe {
            if ffi::secp256k1_ec_pubkey_tweak_mul(secp.ctx, &mut self.0, other.as_c_ptr()) == 1 {
                Ok(())
            } else {
                Err(Error::InvalidTweak)
            }
        }
    }

    /// Adds a second key to this one, returning the sum. Returns an error if
    /// the result would be the point at infinity, i.e. we are adding this point
    /// to its own negation
    pub fn combine(&self, other: &PublicKey) -> Result<PublicKey, Error> {
        PublicKey::combine_keys(&[self, other])
    }

    /// Adds the keys in the provided slice together, returning the sum. Returns
    /// an error if the result would be the point at infinity, i.e. we are adding
    /// a point to its own negation
    pub fn combine_keys(keys: &[&PublicKey]) -> Result<PublicKey, Error> {
        use core::i32::MAX;
        use core::mem::transmute;

        debug_assert!(keys.len() < MAX as usize);
        unsafe {
            let mut ret = ffi::PublicKey::new();
            let ptrs: &[*const ffi::PublicKey] =
                transmute::<&[&PublicKey], &[*const ffi::PublicKey]>(keys);
            if ffi::secp256k1_ec_pubkey_combine(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                ptrs.as_c_ptr(),
                keys.len() as i32,
            ) == 1
            {
                Ok(PublicKey(ret))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }
}

impl CPtr for PublicKey {
    type Target = ffi::PublicKey;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

/// Creates a new public key from a FFI public key
impl From<ffi::PublicKey> for PublicKey {
    #[inline]
    fn from(pk: ffi::PublicKey) -> PublicKey {
        PublicKey(pk)
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for PublicKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "an ASCII hex string representing a public key",
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "a bytestring representing a public key",
                PublicKey::from_slice,
            ))
        }
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<::core::cmp::Ordering> {
        self.serialize().partial_cmp(&other.serialize())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> ::core::cmp::Ordering {
        self.serialize().cmp(&other.serialize())
    }
}
