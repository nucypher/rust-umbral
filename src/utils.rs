use crate::curve::CurveScalar;

pub fn lambda_coeff(id_i: &CurveScalar, selected_ids: &[CurveScalar]) -> CurveScalar {
    let mut res = CurveScalar::one();
    for id_j in selected_ids {
        if id_j != id_i {
            res = &res * id_j * &(id_j - id_i).invert().unwrap();
        }
    }
    res
}

pub fn poly_eval(coeff: &[CurveScalar], x: &CurveScalar) -> CurveScalar {
    let mut result = coeff[coeff.len() - 1];
    for i in (0..coeff.len() - 1).rev() {
        result = (&result * &x) + &coeff[i];
    }
    result
}
