use crate::curve::CurveScalar;

pub fn poly_eval(coeff: &[CurveScalar], x: &CurveScalar) -> CurveScalar {
    let mut result = coeff[coeff.len()-1];
    for i in (0..coeff.len()-1).rev() {
        result = (&result * &x) + &coeff[i];
    }
    result
}
