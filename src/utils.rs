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
