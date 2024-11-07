use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr,
};
use ark_ff::{One, Zero};
use gs_ppe::{Equation, Matrix};
use std::ops::{Mul, Neg};

use crate::Params;

/// E_DH: e(G^-1, Y) e(X, H) = 1
/// It is equivalent to E_r.
pub(crate) fn equation_dh<E: Pairing>(pp: &Params<E>) -> Equation<E> {
    Equation::<E>::new(
        vec![pp.pps.g.mul(E::ScalarField::one().neg()).into()],
        vec![pp.pps.h],
        Matrix::new(&[[E::ScalarField::zero()]]),
        PairingOutput::zero(),
    )
}
/// E_u: e(T^-1, Y) e(X, H^-1) = e(U, H)^-1
pub(crate) fn equation_u<E: Pairing>(pp: &Params<E>, u: &<E as Pairing>::G1Affine) -> Equation<E> {
    Equation::<E>::new(
        vec![pp.pps.t.mul(E::ScalarField::one().neg()).into()],
        vec![pp.pps.h.mul(E::ScalarField::one().neg()).into()],
        Matrix::new(&[[E::ScalarField::zero()]]),
        E::pairing(u, pp.pps.h).mul(E::ScalarField::one().neg()),
    )
}

/// Define E_at(A; D) : e(A, Y) e(A, D) = 1, where A and D are variables X1 and Y1.
pub(crate) fn equation_at<E: Pairing>(y: <E as Pairing>::G2Affine) -> Equation<E> {
    // From GS Proof notation:
    // e(A1, Y1) e(X1, B1) e(X1, Y1)^1
    // -> e(0, d) e(a, y) e(a, d)
    // -> e(a, y) e(a, d)
    //
    // so we have A1 = 0, B1 = d, X1 = a, and Y1 = d
    Equation::<E>::new(
        vec![<E as Pairing>::G1Affine::zero()],
        vec![y],
        Matrix::new(&[[E::ScalarField::one()]]),
        PairingOutput::zero(),
    )
}

/// Define E_a(A, M; S, D) : e(T^-1, S) e(A, Y) e(M, H^-1) e(A, D) = e(K, H),
/// where A, M, S, and D are variables X1, X2, Y1, and Y2.
pub(crate) fn equation_a<E: Pairing>(pp: &Params<E>, y: <E as Pairing>::G2Affine) -> Equation<E> {
    // From GS Proof notation:
    // e(A1, Y1) e(A2, Y2) e(X1, B1) e(X2, B2) e(X1, Y2)^1
    // -> e(t^-1, s) e(0, d) e(a, y) e(m, h^-1) e(a, d)
    //
    // so we have:
    // A1 = t^-1, A2 = 0, B1 = y, B2 = h^-1,
    // Y1 = s, Y2 = d, X1 = a, X2 = m
    // gamma is matrix of (2 x 2) = [[0, 1], [0, 0]]
    Equation::<E>::new(
        vec![
            pp.pps.t.mul(E::ScalarField::one().neg()).into(),
            <E as Pairing>::G1Affine::zero(),
        ],
        vec![y, pp.pps.h.mul(E::ScalarField::one().neg()).into()],
        Matrix::new(&[
            [E::ScalarField::zero(), E::ScalarField::one()],
            [E::ScalarField::zero(), E::ScalarField::zero()],
        ]),
        E::pairing(pp.pps.k, pp.pps.h),
    )
}

/// E_b: e(F^-1, Y) e(X, H) = 1
pub(crate) fn equation_b<E: Pairing>(pp: &Params<E>) -> Equation<E> {
    Equation::<E>::new(
        vec![pp.pps.f.mul(E::ScalarField::one().neg()).into()],
        vec![pp.pps.h],
        Matrix::new(&[[E::ScalarField::zero()]]),
        PairingOutput::zero(),
    )
}

/// Define E_a~(A; S, D) : e(T^-1, S) e(A, Y) e(A, D) = e(K + M, H),
/// where A, S, and D are variables X1, Y1, and Y2.
///
/// This should be used in function `AdPrC` but we dont know `m`. So we compute the target from LHS of the equation.
pub(crate) fn equation_a_tide_from_lhs<E: Pairing>(
    pp: &Params<E>,
    s: <E as Pairing>::G2Affine,
    a: <E as Pairing>::G1Affine,
    d: <E as Pairing>::G2Affine,
    y: <E as Pairing>::G2Affine,
) -> Equation<E> {
    // From GS Proof notation:
    // e(A1, Y1) e(X1, B1) e(X1, Y2)^1
    // -> e(t^-1, s) e(0, d) e(a, y) e(a, d)
    //
    // so we have A1 = t^-1, A2 = 0, B1 = y, Y1 = s, Y2 = d, X1 = a
    // gamma is matrix of (2 x 2) = [[0, 1], [0, 0]]
    let t_neg = pp.pps.t.mul(E::ScalarField::one().neg());
    Equation::<E>::new(
        vec![t_neg.into(), <E as Pairing>::G1Affine::zero()],
        vec![y],
        Matrix::new(&[
            [E::ScalarField::zero(), E::ScalarField::one()],
            [E::ScalarField::zero(), E::ScalarField::zero()],
        ]),
        E::pairing(t_neg, s) + E::pairing(a, y) + E::pairing(a, d),
    )
}

/// Define E_a~(A; S, D) : e(T^-1, S) e(A, Y) e(A, D) = e(K + M, H),
/// where A, S, and D are variables X1, Y1, and Y2.
///
/// This should be used in function `AdPrC_M`. As `m` is known, we can compute the target from RHS of the equation.
pub(crate) fn equation_a_tide_from_rhs<E: Pairing>(
    pp: &Params<E>,
    y: <E as Pairing>::G2Affine,
    m: <E as Pairing>::G1Affine,
) -> Equation<E> {
    // From GS Proof notation:
    // e(A1, Y1) e(X1, B1) e(X1, Y2)^1
    // -> e(t^-1, s) e(0, d) e(a, y) e(a, d)
    //
    // so we have A1 = t^-1, A2 = 0, B1 = y, Y1 = s, Y2 = d, X1 = a
    // gamma is matrix of (2 x 2) = [[0, 1], [0, 0]]
    let t_neg = pp.pps.t.mul(E::ScalarField::one().neg());
    Equation::<E>::new(
        vec![t_neg.into(), <E as Pairing>::G1Affine::zero()],
        vec![y],
        Matrix::new(&[
            [E::ScalarField::zero(), E::ScalarField::one()],
            [E::ScalarField::zero(), E::ScalarField::zero()],
        ]),
        E::pairing(pp.pps.k + m, pp.pps.h),
    )
}

/// Define E_a_bar(M) : e(M, H^-1) = e(A, Y + D)^-1 e(K, H) e(T, S),
/// where M is variable X1.
pub(crate) fn equation_a_bar_from_rhs<E: Pairing>(
    pp: &Params<E>,
    y: <E as Pairing>::G2Affine,
    a: <E as Pairing>::G1Affine,
    d: <E as Pairing>::G2Affine,
    s: <E as Pairing>::G2Affine,
) -> Equation<E> {
    Equation::<E>::new(
        vec![],
        vec![pp.pps.h.mul(E::ScalarField::one().neg()).into()],
        Matrix::new(&[[]]),
        E::pairing(a, y + d).neg().mul(E::ScalarField::one().neg())
            + E::pairing(pp.pps.k, pp.pps.h)
            + E::pairing(pp.pps.t, s),
    )
}

/// Define E_a_bar(M) : e(M, H^-1) = e(A, Y + D)^-1 e(K, H) e(T, S),
/// where M is variable X1.
pub(crate) fn equation_a_bar_from_lhs<E: Pairing>(
    pp: &Params<E>,
    m: <E as Pairing>::G1Affine,
) -> Equation<E> {
    Equation::<E>::new(
        vec![],
        vec![pp.pps.h.mul(E::ScalarField::one().neg()).into()],
        Matrix::new(&[[]]),
        E::pairing(m, pp.pps.h)
            .neg()
            .mul(E::ScalarField::one().neg()),
    )
}
