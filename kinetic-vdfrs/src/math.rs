use num_bigint::BigInt;
use num_traits::{Zero, One, Signed};

/// Computes the integer fourth root `floor(sqrt(sqrt(n)))`.
pub fn isqrt_fourth(n: &BigInt) -> BigInt {
    let s1 = n.sqrt();
    s1.sqrt()
}

/// Performs partial Extended Euclidean Algorithm until remainder `r1 <= L`.
pub fn xgcd_partial(r2: &BigInt, r1: &BigInt, l: &BigInt) -> (BigInt, BigInt, BigInt, BigInt) {
    let mut r2_cur = r2.clone();
    let mut r1_cur = r1.clone();
    let mut co2 = BigInt::zero();
    let mut co1 = BigInt::from(-1);

    while !r1_cur.is_zero() && &r1_cur > l {
        let q = &r2_cur / &r1_cur;
        let t1 = &r2_cur - &q * &r1_cur;
        let t2 = &co2 - &q * &co1;
        r2_cur = r1_cur;
        r1_cur = t1;
        co2 = co1;
        co1 = t2;
    }
    (co2, co1, r2_cur, r1_cur)
}

/// A Binary Quadratic Form `ax^2 + bxy + cy^2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    /// The `a` coefficient.
    pub a: BigInt,
    /// The `b` coefficient.
    pub b: BigInt,
    /// The `c` coefficient.
    pub c: BigInt,
}

impl Form {
    /// Creates a new Form.
    pub fn new(a: BigInt, b: BigInt, c: BigInt) -> Self {
        Self { a, b, c }
    }

    /// Returns the identity element for a given discriminant `d`.
    /// 
    /// The identity form is `(1, 1, (1 - D) / 4)`.
    pub fn identity(d: &BigInt) -> Self {
        let one = BigInt::one();
        let four = BigInt::from(4);
        let c = (&one - d) / four;
        Self {
            a: one.clone(),
            b: one,
            c,
        }
    }

    /// Constructs a form `(a, b, c)` from `a`, `b`, and discriminant `d` if `(b^2 - d)` is divisible by `4a`.
    pub fn from_abd(a: &BigInt, b: &BigInt, d: &BigInt) -> Option<Self> {
        if a.is_zero() {
            return None;
        }
        let num = b * b - d;
        let den = a * BigInt::from(4);
        if &num % &den != BigInt::zero() {
            return None;
        }
        let c = num / den;
        Some(Self {
            a: a.clone(),
            b: b.clone(),
            c,
        })
    }

    /// Returns the canonical generator form `(2, 1, (1 - D) / 8)` for prime discriminant `D = -p` where `p = 7 mod 8`.
    pub fn generator(d: &BigInt) -> Option<Self> {
        let num = BigInt::one() - d;
        let eight = BigInt::from(8);
        if &num % &eight != BigInt::zero() {
            return None;
        }
        let c = num / eight;
        Some(Self {
            a: BigInt::from(2),
            b: BigInt::one(),
            c,
        })
    }

    /// Checks if the form is reduced: `-a < b <= a`, `a <= c`, and if `a == c` then `b >= 0`.
    pub fn is_reduced(&self) -> bool {
        if self.a <= BigInt::zero() || self.c <= BigInt::zero() {
            return false;
        }
        if self.b <= -(&self.a) || self.b > self.a {
            return false;
        }
        if self.a > self.c {
            return false;
        }
        if self.a == self.c && self.b < BigInt::zero() {
            return false;
        }
        true
    }

    /// Reduces this form in place according to the standard Euclidean Gauss algorithm
    /// for imaginary quadratic class groups.
    pub fn reduce(&mut self, d: &BigInt) {
        use num_integer::Integer;
        let two = BigInt::from(2);
        let four = BigInt::from(4);

        loop {
            // Step 1: normalize b into (-a, a]
            let a2 = &self.a * &two;
            let s = (&self.a - &self.b).div_floor(&a2);
            let b_new = &self.b + &a2 * &s;
            let c_new = (&b_new * &b_new - d) / (&self.a * &four);
            let a_new = self.a.clone();

            // Step 2: if a > c, swap a and c, negate b, and loop
            if a_new > c_new {
                self.a = c_new;
                self.c = a_new;
                self.b = -b_new;
                continue;
            }

            // Step 3: if a == c and b < 0, negate b
            if a_new == c_new && b_new.is_negative() {
                self.b = -b_new;
            } else {
                self.b = b_new;
            }
            self.a = a_new;
            self.c = c_new;
            break;
        }
    }

    /// Shanks' NUDUPL algorithm for fast squaring of binary quadratic forms.
    pub fn nudupl(&self, d: &BigInt, l: &BigInt) -> Form {
        use num_integer::Integer;
        let two = BigInt::from(2);
        let four = BigInt::from(4);

        let mut a1 = self.a.clone();
        let mut c1 = self.c.clone();

        let ext = if self.b.is_negative() {
            let b_abs = -(&self.b);
            let e = b_abs.extended_gcd(&a1);
            (-e.x, e.gcd)
        } else {
            let e = self.b.extended_gcd(&a1);
            (e.x, e.gcd)
        };

        let mut k = -(&ext.0 * &c1);
        let s = ext.1;

        if s != BigInt::one() {
            a1 /= &s;
            c1 *= &s;
        }

        k = k.mod_floor(&a1);

        if a1 < *l {
            let t = &a1 * &k;
            let res_a = &a1 * &a1;
            let cb = &two * &t + &self.b;
            let res_c = ((&self.b + &t) * &k + &c1) / &a1;
            Form::new(res_a, cb, res_c)
        } else {
            let (co2, co1, _r2, r1) = xgcd_partial(&a1, &k, l);

            let m2 = (&self.b * &r1 - &c1 * &co1) / &a1;
            let mut res_a = &r1 * &r1 - &co1 * &m2;
            if !co1.is_negative() {
                res_a = -res_a;
            }

            let cb_num = &two * (&a1 * &r1 - &res_a * &co2);
            let cb = (cb_num / &co1 - &self.b).mod_floor(&(&res_a * &two));

            let mut res_c = (&cb * &cb - d) / (&res_a * &four);

            if res_a.is_negative() {
                res_a = -res_a;
                res_c = -res_c;
            }

            Form::new(res_a, cb, res_c)
        }
    }

    /// Shanks' NUCOMP algorithm for fast composition of binary quadratic forms.
    pub fn nucomp(&self, other: &Form, d: &BigInt, l: &BigInt) -> Form {
        use num_integer::Integer;
        if self.a > other.a {
            return other.nucomp(self, d, l);
        }

        let two = BigInt::from(2);
        let four = BigInt::from(4);

        let mut a1 = self.a.clone();
        let mut a2 = other.a.clone();
        let mut c2 = other.c.clone();

        let ss = (&self.b + &other.b) / &two;
        let m = (&self.b - &other.b) / &two;

        let t = a2.mod_floor(&a1);
        let (v1, sp) = if t.is_zero() {
            (BigInt::zero(), a1.clone())
        } else {
            let e = t.extended_gcd(&a1);
            (e.x, e.gcd)
        };

        let mut k = (&m * &v1).mod_floor(&a1);

        if sp != BigInt::one() {
            let e2 = ss.extended_gcd(&sp);
            let v2 = e2.x;
            let u2 = e2.y;
            let s = e2.gcd;
            k = &k * &u2 - &v2 * &c2;
            if s != BigInt::one() {
                a1 /= &s;
                a2 /= &s;
                c2 *= &s;
            }
            k = k.mod_floor(&a1);
        }

        if a1 < *l {
            let t_val = &a2 * &k;
            let ca = &a2 * &a1;
            let cb = &two * &t_val + &other.b;
            let cc = ((&other.b + &t_val) * &k + &c2) / &a1;
            Form::new(ca, cb, cc)
        } else {
            let (co2, co1, _r2, r1) = xgcd_partial(&a1, &k, l);

            let m1 = (&m * &co1 + &a2 * &r1) / &a1;
            let m2 = (&ss * &r1 - &c2 * &co1) / &a1;

            let mut ca = &r1 * &m1 - &co1 * &m2;
            if !co1.is_negative() {
                ca = -ca;
            }

            let t_val = &a2 * &r1;
            let cb_num = &two * (&t_val - &ca * &co2);
            let cb = (cb_num / &co1 - &other.b).mod_floor(&(&ca * &two));

            let mut cc = (&cb * &cb - d) / (&ca * &four);

            if ca.is_negative() {
                ca = -ca;
                cc = -cc;
            }

            Form::new(ca, cb, cc)
        }
    }

    /// Fast exponentiation using NUDUPL and NUCOMP with threshold reduction matching chiavdf's `FastPowFormNucomp`.
    pub fn fast_pow(&self, exp: &num_bigint::BigUint, d: &BigInt, l: &BigInt) -> Form {
        use num_traits::Zero;
        if exp.is_zero() {
            return Self::identity(d);
        }

        let mut res = self.clone();
        let max_bits = d.abs().bits() / 2;
        let num_bits = exp.bits();

        if num_bits > 1 {
            for i in (0..num_bits - 1).rev() {
                res = res.nudupl(d, l);
                if res.a.bits() > max_bits {
                    res.reduce(d);
                }

                if exp.bit(i) {
                    res = res.nucomp(self, d, l);
                }
            }
        }

        res.reduce(d);
        res
    }

    /// Raises this form to the power of a large non-negative integer `exp` using binary exponentiation.
    pub fn pow(&self, exp: &num_bigint::BigUint, d: &BigInt) -> Self {
        let l = isqrt_fourth(&d.abs());
        self.fast_pow(exp, d, &l)
    }

    /// Composes this form with another form, returning a new reduced form.
    pub fn compose(&self, other: &Form, d_disc: &BigInt) -> Form {
        let l = isqrt_fourth(&d_disc.abs());
        let mut form = self.nucomp(other, d_disc, &l);
        form.reduce(d_disc);
        form
    }

    /// Optimized squaring of a form (equivalent to `self.compose(self, d_disc)` but faster).
    pub fn square(&self, d_disc: &BigInt) -> Form {
        let l = isqrt_fourth(&d_disc.abs());
        let mut form = self.nudupl(d_disc, &l);
        form.reduce(d_disc);
        form
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduction_valid_negative_discriminant() {
        let d = BigInt::from(-71);
        let mut form = Form::new(BigInt::from(2), BigInt::from(1), BigInt::from(9));
        form.reduce(&d);
        assert_eq!(form.a, BigInt::from(2));
        assert_eq!(form.b, BigInt::from(1));
        assert_eq!(form.c, BigInt::from(9)); // It is already reduced
    }

    #[test]
    fn test_compose_and_square() {
        let d = BigInt::from(-71);
        let id = Form::identity(&d); // (1, 1, 18)
        let f2 = Form::new(BigInt::from(2), BigInt::from(1), BigInt::from(9));
        
        // Compose with identity should equal itself
        let comp1 = id.compose(&f2, &d);
        assert_eq!(comp1, f2);

        // Square
        let sq = f2.square(&d);
        assert_eq!(sq, Form::new(BigInt::from(4), BigInt::from(-3), BigInt::from(5)));

        // Compose f2 with itself should equal square
        let comp2 = f2.compose(&f2, &d);
        assert_eq!(comp2, sq);

        // f2 * f2^-1 should equal identity
        let f2_inv = Form::new(f2.a.clone(), -f2.b.clone(), f2.c.clone());
        let comp3 = f2.compose(&f2_inv, &d);
        assert_eq!(comp3, id);
    }
}

