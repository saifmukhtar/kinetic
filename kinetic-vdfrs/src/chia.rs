//! Chia-compatible discriminant generation, form serialization, and Wesolowski verification.

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use sha2::{Digest, Sha256};

use crate::math::Form;

const B_BITS: usize = 264;
const BQFC_FORM_SIZE: usize = 100;

const BQFC_B_SIGN: u8 = 1 << 0;
const BQFC_T_SIGN: u8 = 1 << 1;
const BQFC_IS_1: u8 = 1 << 2;
const BQFC_IS_GEN: u8 = 1 << 3;

/// Computes the integer square root of a non-negative `BigInt`.
fn isqrt(n: &BigInt) -> BigInt {
    if n.is_negative() {
        panic!("isqrt on negative number");
    }
    if n.is_zero() {
        return BigInt::zero();
    }
    let uint_sqrt = n.to_biguint().unwrap().sqrt();
    BigInt::from_biguint(Sign::Plus, uint_sqrt)
}

/// Miller-Rabin probabilistic primality test on `BigUint`.
pub fn is_probable_prime(n: &BigUint, rounds: usize) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Small prime trial division for speed
    let small_primes = [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
    for &p in &small_primes {
        let bp = BigUint::from(p);
        if n == &bp {
            return true;
        }
        if (n % &bp).is_zero() {
            return false;
        }
    }

    // n - 1 = 2^r * d
    let n_minus_1 = n - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut r = 0usize;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    // Deterministic small bases plus step bases
    let bases = [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    let test_rounds = std::cmp::max(rounds, bases.len());

    for i in 0..test_rounds {
        let a = if i < bases.len() {
            BigUint::from(bases[i])
        } else {
            BigUint::from((i as u32) * 2 + 39)
        };
        if &a >= n {
            break;
        }

        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }

        let mut composite = true;
        for _ in 0..(r - 1) {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }

        if composite {
            return false;
        }
    }

    true
}

/// Generates a pseudoprime matching Chia's `HashPrime` algorithm.
pub fn hash_prime(seed: &[u8], length_bits: usize, bitmask: &[usize]) -> BigUint {
    assert_eq!(length_bits % 8, 0, "length_bits must be a multiple of 8");
    let mut sprout = seed.to_vec();

    loop {
        let mut blob = Vec::new();
        while blob.len() * 8 < length_bits {
            // Increment sprout (big-endian)
            for i in (0..sprout.len()).rev() {
                sprout[i] = sprout[i].wrapping_add(1);
                if sprout[i] != 0 {
                    break;
                }
            }
            let hash = Sha256::digest(&sprout);
            let needed = (length_bits / 8) - blob.len();
            let take = std::cmp::min(hash.len(), needed);
            blob.extend_from_slice(&hash[..take]);
        }

        let mut p = BigUint::from_bytes_be(&blob);
        for &b in bitmask {
            p.set_bit(b as u64, true);
        }
        p.set_bit(0, true); // Force odd

        if is_probable_prime(&p, 25) {
            return p;
        }
    }
}

/// Creates a negative prime discriminant from a seed byte slice matching Chia's `CreateDiscriminant`.
pub fn create_discriminant(seed: &[u8], length_bits: usize) -> BigInt {
    if seed.is_empty() {
        panic!("seed cannot be empty");
    }
    if length_bits == 0 || length_bits % 8 != 0 {
        panic!("invalid length_bits");
    }

    let p = hash_prime(seed, length_bits, &[0, 1, 2, length_bits - 1]);
    -BigInt::from_biguint(Sign::Plus, p)
}

/// Performs partial Extended Euclidean Algorithm for form compression.
fn xgcd_partial(a: &BigInt, b: &BigInt, l: &BigInt) -> (BigInt, BigInt, BigInt, BigInt) {
    let mut r2 = a.clone();
    let mut r1 = b.clone();
    let mut co2 = BigInt::zero();
    let mut co1 = BigInt::from(-1);

    while r1 > BigInt::zero() && &r1 > l {
        let q = &r2 / &r1;
        let t1 = &r2 - &q * &r1;
        let t2 = &co2 - &q * &co1;
        r2 = r1;
        r1 = t1;
        co2 = co1;
        co1 = t2;
    }
    (co2, co1, r2, r1)
}

/// Structure holding compressed quadratic form components.
#[derive(Debug, Clone)]
pub struct CompressedForm {
    /// Compressed `a` coefficient.
    pub a: BigInt,
    /// Partial quotient parameter `t`.
    pub t: BigInt,
    /// Common divisor `g = gcd(a, t)`.
    pub g: BigInt,
    /// Remainder `b0 = b / a'`.
    pub b0: BigInt,
    /// Sign of original `b` coefficient.
    pub b_sign: bool,
}


/// Compresses a reduced form `(a, b)` into components.
pub fn bqfc_compr(a: &BigInt, b: &BigInt) -> CompressedForm {
    if a == b {
        return CompressedForm {
            a: a.clone(),
            t: BigInt::zero(),
            g: BigInt::zero(),
            b0: BigInt::zero(),
            b_sign: false,
        };
    }

    let sign = b.is_negative();
    let a_sqrt = isqrt(a);
    let a_copy = a.clone();
    let b_copy = if sign { -b } else { b.clone() };

    let (_dummy, mut t, _r2, _r1) = xgcd_partial(&a_copy, &b_copy, &a_sqrt);
    t = -t;

    let g = a.gcd(&t);
    let (out_a, out_t, mut out_b0) = if g == BigInt::one() {
        (a.clone(), t, BigInt::zero())
    } else {
        let out_a = a / &g;
        let out_t = &t / &g;
        let b0 = b / &out_a;
        (out_a, out_t, b0)
    };

    if sign {
        out_b0 = -out_b0;
    }

    CompressedForm {
        a: out_a,
        t: out_t,
        g,
        b0: out_b0,
        b_sign: sign,
    }
}

/// Decompresses components into a reduced form `(a, b)`.
pub fn bqfc_decompr(c: &CompressedForm, d: &BigInt) -> Result<(BigInt, BigInt), &'static str> {
    if c.t.is_zero() {
        return Ok((c.a.clone(), c.a.clone()));
    }

    if c.a.is_zero() {
        return Err("c.a is zero");
    }

    let mut t = c.t.clone();
    if t.is_negative() {
        t += &c.a;
    }

    // Extended GCD for inverse mod c.a
    let ext = t.extended_gcd(&c.a);
    if ext.gcd != BigInt::one() {
        return Err("t and a are not coprime");
    }
    let mut t_inv = ext.x;
    if t_inv.is_negative() {
        t_inv += &c.a;
    }


    let d_mod_a = d.mod_floor(&c.a);
    let t_sq = (&c.t * &c.t).mod_floor(&c.a);
    let tmp = (t_sq * d_mod_a).mod_floor(&c.a);

    let root = isqrt(&tmp);
    if &root * &root != tmp {
        return Err("tmp is not a perfect square");
    }

    let mut out_b = (&root * &t_inv).mod_floor(&c.a);
    let out_a = if c.g > BigInt::one() {
        &c.a * &c.g
    } else {
        c.a.clone()
    };

    if c.b0 > BigInt::zero() {
        out_b += &c.a * &c.b0;
    }

    if c.b_sign {
        out_b = -out_b;
    }

    Ok((out_a, out_b))
}

/// Exports a `BigInt` as little-endian bytes into `out_str` with zero padding (matching `bqfc.c`).
fn export_le(val: &BigInt, out_str: &mut [u8], offset: &mut usize, size: usize) -> Result<(), &'static str> {
    let bytes = val.to_biguint().unwrap_or_else(BigUint::zero).to_bytes_le();
    if bytes.len() > size {
        return Err("integer overflow exporting bytes");
    }
    out_str[*offset..*offset + bytes.len()].copy_from_slice(&bytes);
    out_str[*offset + bytes.len()..*offset + size].fill(0);
    *offset += size;
    Ok(())
}

/// Imports a little-endian `BigInt` from a byte slice (matching `bqfc.c`).
fn import_le(data: &[u8]) -> BigInt {
    BigInt::from_biguint(Sign::Plus, BigUint::from_bytes_le(data))
}

/// Serializes a reduced binary quadratic form into Chia's 100-byte format.
pub fn serialize_form(form: &Form, d_bits: usize) -> Result<Vec<u8>, &'static str> {
    let mut res = vec![0u8; BQFC_FORM_SIZE];
    if form.b == BigInt::one() && form.a <= BigInt::from(2) {
        res[0] = if form.a == BigInt::from(2) {
            BQFC_IS_GEN
        } else {
            BQFC_IS_1
        };
        return Ok(res);
    }

    let d_bits_rounded = (d_bits + 31) & !31;
    let compr = bqfc_compr(&form.a, &form.b);

    res[0] = if compr.b_sign { BQFC_B_SIGN } else { 0 };
    if compr.t.is_negative() {
        res[0] |= BQFC_T_SIGN;
    }

    let g_biguint = compr.g.to_biguint().unwrap_or_else(BigUint::zero);
    let g_size = if compr.g.is_zero() {
        0
    } else {
        (g_biguint.bits() as usize + 7) / 8 - 1
    };
    res[1] = g_size as u8;

    let mut offset = 2;
    let a_bytes_len = d_bits_rounded / 16 - g_size;
    let t_bytes_len = d_bits_rounded / 32 - g_size;
    let g_bytes_len = g_size + 1;

    export_le(&compr.a, &mut res, &mut offset, a_bytes_len)?;
    let t_abs = compr.t.abs();
    export_le(&t_abs, &mut res, &mut offset, t_bytes_len)?;
    export_le(&compr.g, &mut res, &mut offset, g_bytes_len)?;
    let b0_abs = compr.b0.abs();
    export_le(&b0_abs, &mut res, &mut offset, g_bytes_len)?;

    Ok(res)
}

/// Deserializes a Chia 100-byte compressed form into a reduced `Form`.
pub fn deserialize_form(d: &BigInt, bytes: &[u8]) -> Result<Form, &'static str> {
    if bytes.len() != BQFC_FORM_SIZE {
        return Err("invalid form byte size");
    }

    if bytes[0] & (BQFC_IS_1 | BQFC_IS_GEN) != 0 {
        let a = if bytes[0] & BQFC_IS_GEN != 0 {
            BigInt::from(2)
        } else {
            BigInt::from(1)
        };
        let b = BigInt::one();
        return Form::from_abd(&a, &b, d).ok_or("invalid form parameters");
    }

    let d_bits = d.abs().to_biguint().unwrap().bits() as usize;
    let d_bits_rounded = (d_bits + 31) & !31;

    let g_size = bytes[1] as usize;
    if g_size >= d_bits_rounded / 32 {
        return Err("invalid g_size");
    }

    let mut offset = 2;
    let a_len = d_bits_rounded / 16 - g_size;
    let t_len = d_bits_rounded / 32 - g_size;
    let g_len = g_size + 1;

    if offset + a_len + t_len + 2 * g_len > bytes.len() {
        return Err("corrupted form byte bounds");
    }

    let a_part = import_le(&bytes[offset..offset + a_len]);
    offset += a_len;

    let mut t_part = import_le(&bytes[offset..offset + t_len]);
    offset += t_len;

    let g_part = import_le(&bytes[offset..offset + g_len]);
    offset += g_len;

    let b0_part = import_le(&bytes[offset..offset + g_len]);

    let b_sign = (bytes[0] & BQFC_B_SIGN) != 0;
    if (bytes[0] & BQFC_T_SIGN) != 0 {
        t_part = -t_part;
    }

    let compr = CompressedForm {
        a: a_part,
        t: t_part,
        g: g_part,
        b0: b0_part,
        b_sign,
    };

    let (dec_a, dec_b) = bqfc_decompr(&compr, d)?;
    let form = Form::from_abd(&dec_a, &dec_b, d).ok_or("decompressed form invalid")?;
    if !form.is_reduced() {
        return Err("decompressed form is not reduced");
    }

    Ok(form)
}


/// Derives the 264-bit Fiat-Shamir prime challenge `B` from serialized forms `x` and `y`.
pub fn get_b(d: &BigInt, x: &Form, y: &Form) -> Result<BigUint, &'static str> {
    let d_bits = d.abs().to_biguint().unwrap().bits() as usize;
    let ser_x = serialize_form(x, d_bits)?;
    let ser_y = serialize_form(y, d_bits)?;

    let mut concat = ser_x;
    concat.extend_from_slice(&ser_y);

    Ok(hash_prime(&concat, B_BITS, &[B_BITS - 1]))
}

/// Verifies a Wesolowski VDF proof against challenge generator `x`, target `y`, and `proof` form `pi`.
pub fn verify_wesolowski(
    d: &BigInt,
    x: &Form,
    y: &Form,
    proof: &Form,
    iterations: u64,
) -> Result<bool, &'static str> {
    let b = get_b(d, x, y)?;

    // r = 2^iterations mod B
    let r = BigUint::from(2u32).modpow(&BigUint::from(iterations), &b);

    // f1 = proof^B
    let f1 = proof.pow(&b, d);
    // f2 = x^r
    let f2 = x.pow(&r, d);

    let result = f1.compose(&f2, d);
    Ok(&result == y)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminant_chia_test_vector() {
        let challenge = [42u8; 32];
        let d = create_discriminant(&challenge, 1024);
        assert!(d.is_negative());
        let p_bytes = d.abs().to_biguint().unwrap().to_bytes_be();

        let expected_prefix = [
            237, 89, 165, 1, 5, 76, 207, 152, 207, 134, 182, 117, 254, 184, 124, 248,
        ];
        assert_eq!(&p_bytes[0..16], &expected_prefix[..]);
    }
}
