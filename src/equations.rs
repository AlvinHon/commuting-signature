//! Defines equations for the proof system.

use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr,
};
use ark_std::{One, Zero};
use gs_ppe::{Equation, Matrix};
use std::ops::{Mul, Neg};

use crate::Params;

/// E_DH: e(G^-1, Y) e(X, H) = 1
/// It is equivalent to E_r.
///
/// Formula (10) in section 8.1 of the paper.
/// Same as the formula (12) `E_r` in section 8.2 of the paper.
pub(crate) fn equation_dh<E: Pairing>(pp: &Params<E>) -> Equation<E> {
    Equation::<E>::new(
        vec![pp.pps.g.mul(E::ScalarField::one().neg()).into()],
        vec![pp.pps.h.into()],
        Matrix::new(&[[E::ScalarField::zero()]]),
        PairingOutput::zero(),
    )
}

/// E_u: e(T^-1, Y) e(X, H^-1) = e(U, H)^-1
///
/// Formula (11) in section 8.1 of the paper.
pub(crate) fn equation_u<E: Pairing>(pp: &Params<E>, u: &<E as Pairing>::G1) -> Equation<E> {
    Equation::<E>::new(
        vec![pp.pps.t.mul(E::ScalarField::one().neg()).into()],
        vec![pp.pps.h.mul(E::ScalarField::one().neg()).into()],
        Matrix::new(&[[E::ScalarField::zero()]]),
        E::pairing(u, pp.pps.h).mul(E::ScalarField::one().neg()),
    )
}

/// Define E_at(A; D) : e(A, Y) e(A, D) = 1, where A and D are variables X1 and Y1.
///
/// Formula (14) in section 8.2 of the paper.
pub(crate) fn equation_at<E: Pairing>(y: <E as Pairing>::G2) -> Equation<E> {
    // From GS Proof notation:
    // e(A1, Y1) e(X1, B1) e(X1, Y1)^1
    // -> e(0, d) e(a, y) e(a, d)
    // -> e(a, y) e(a, d)
    //
    // so we have A1 = 0, B1 = y, X1 = a, and Y1 = d
    Equation::<E>::new(
        vec![<E as Pairing>::G1Affine::zero()],
        vec![y.into()],
        Matrix::new(&[[E::ScalarField::one()]]),
        PairingOutput::zero(),
    )
}

/// Define E_a(A, M; S, D) : e(T^-1, S) e(A, Y) e(M, H^-1) e(A, D) = e(K, H),
/// where A, M, S, and D are variables X1, X2, Y1, and Y2.
///
/// Formula (12) in section 8.2 of the paper.
pub(crate) fn equation_a<E: Pairing>(pp: &Params<E>, y: <E as Pairing>::G2) -> Equation<E> {
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
        vec![y.into(), pp.pps.h.mul(E::ScalarField::one().neg()).into()],
        Matrix::new(&[
            [E::ScalarField::zero(), E::ScalarField::one()],
            [E::ScalarField::zero(), E::ScalarField::zero()],
        ]),
        E::pairing(pp.pps.k, pp.pps.h),
    )
}

/// E_b: e(F^-1, Y) e(X, H) = 1
///
/// Formula (12) in section 8.2 of the paper.
pub(crate) fn equation_b<E: Pairing>(pp: &Params<E>) -> Equation<E> {
    Equation::<E>::new(
        vec![pp.pps.f.mul(E::ScalarField::one().neg()).into()],
        vec![pp.pps.h.into()],
        Matrix::new(&[[E::ScalarField::zero()]]),
        PairingOutput::zero(),
    )
}

/// Define E_a~(A; S, D) : e(T^-1, S) e(A, Y) e(A, D) = e(K + M, H),
/// where A, S, and D are variables X1, Y1, and Y2.
///
/// This should be used in function `AdPrC` but we dont know `m`. So we compute the target from LHS of the equation.
///
/// Formula in section 8.3 of the paper.
pub(crate) fn equation_a_tide_from_lhs<E: Pairing>(
    pp: &Params<E>,
    s: <E as Pairing>::G2,
    a: <E as Pairing>::G1,
    d: <E as Pairing>::G2,
    y: <E as Pairing>::G2,
) -> Equation<E> {
    // From GS Proof notation:
    // e(A1, Y1) e(X1, B1) e(X1, Y2)^1
    // -> e(t^-1, s) e(0, d) e(a, y) e(a, d)
    //
    // so we have A1 = t^-1, A2 = 0, B1 = y, Y1 = s, Y2 = d, X1 = a
    // gamma is matrix of (1 x 2) = [[0, 1]]
    let t_neg = pp.pps.t.mul(E::ScalarField::one().neg());
    Equation::<E>::new(
        vec![t_neg.into(), <E as Pairing>::G1Affine::zero()],
        vec![y.into()],
        Matrix::new(&[[E::ScalarField::zero(), E::ScalarField::one()]]),
        E::pairing(t_neg, s) + E::pairing(a, y) + E::pairing(a, d),
    )
}

/// Define E_a~(A; S, D) : e(T^-1, S) e(A, Y) e(A, D) = e(K + M, H),
/// where A, S, and D are variables X1, Y1, and Y2.
///
/// This should be used in function `AdPrC_M`. As `m` is known, we can compute the target from RHS of the equation.
///
/// Formula in section 8.3 of the paper.
pub(crate) fn equation_a_tide_from_rhs<E: Pairing>(
    pp: &Params<E>,
    y: <E as Pairing>::G2,
    m: <E as Pairing>::G1,
) -> Equation<E> {
    // From GS Proof notation:
    // e(A1, Y1) e(X1, B1) e(X1, Y2)^1
    // -> e(t^-1, s) e(0, d) e(a, y) e(a, d)
    //
    // so we have A1 = t^-1, A2 = 0, B1 = y, Y1 = s, Y2 = d, X1 = a
    // gamma is matrix of (1 x 2) = [[0, 1]]
    let t_neg = pp.pps.t.mul(E::ScalarField::one().neg());
    Equation::<E>::new(
        vec![t_neg.into(), <E as Pairing>::G1Affine::zero()],
        vec![y.into()],
        Matrix::new(&[[E::ScalarField::zero(), E::ScalarField::one()]]),
        E::pairing(pp.pps.k + m, pp.pps.h),
    )
}

/// Define E_a_bar(M) : e(M, H^-1) = e(A, Y + D)^-1 e(K, H) e(T, S),
/// where M is variable X1.
///
/// Formula in section 8.3 of the paper.
pub(crate) fn equation_a_bar_from_lhs<E: Pairing>(
    pp: &Params<E>,
    m: <E as Pairing>::G1,
) -> Equation<E> {
    Equation::<E>::new(
        vec![],
        vec![pp.pps.h.mul(E::ScalarField::one().neg()).into()],
        Matrix::new(&[[]]),
        E::pairing(m, pp.pps.h.mul(E::ScalarField::one().neg())),
    )
}

/// Define E_a_bar(M) : e(M, H^-1) = e(A, Y + D)^-1 e(K, H) e(T, S),
/// where M is variable X1.
///
/// Formula in section 8.3 of the paper.
pub(crate) fn equation_a_bar_from_rhs<E: Pairing>(
    pp: &Params<E>,
    y: <E as Pairing>::G2,
    a: <E as Pairing>::G1,
    d: <E as Pairing>::G2,
    s: <E as Pairing>::G2,
) -> Equation<E> {
    Equation::<E>::new(
        vec![],
        vec![pp.pps.h.mul(E::ScalarField::one().neg()).into()],
        Matrix::new(&[[]]),
        E::pairing(a, y + d).mul(E::ScalarField::one().neg())
            + E::pairing(pp.pps.k, pp.pps.h)
            + E::pairing(pp.pps.t, s),
    )
}

/// Define E_a_cap(A, M; S, Y, D) : e(T^-1, S) e(M, H^-1) e(A, Y) e(A, D) = e(K, H),
/// where A, M, S, D, Y are variables X1, X2, Y1, Y2, and Y3.
///
/// Formula in section 8.3 of the paper.
pub(crate) fn equation_a_cap<E: Pairing>(pp: &Params<E>) -> Equation<E> {
    // From GS Proof notation:
    // e(A1, Y1) e(A2, Y2) e(A3, Y3) e(X1, B1) e(X2, B2) e(X1, Y2)^1 e(X1, Y3)^1
    // -> e(t^-1, s) e(0, d) e(0, y) e(a, 0) e(m, h^-1) e(a, d)^1 e(a, y)^1
    //
    // so we have A1 = t^-1, A2 = 0, A3 = 0, B1 = 0, B2 = h^-1,
    // Y1 = s, Y2 = d, Y3 = y, X1 = a, X2 = m
    // gamma is matrix of (2 x 3) = [[0, 1, 1], [0, 0, 0]]
    Equation::<E>::new(
        vec![
            pp.pps.t.mul(E::ScalarField::one().neg()).into(),
            <E as Pairing>::G1Affine::zero(),
            <E as Pairing>::G1Affine::zero(),
        ],
        vec![
            <E as Pairing>::G2Affine::zero(),
            pp.pps.h.mul(E::ScalarField::one().neg()).into(),
        ],
        Matrix::new(&[
            [
                E::ScalarField::zero(),
                E::ScalarField::one(),
                E::ScalarField::one(),
            ],
            [
                E::ScalarField::zero(),
                E::ScalarField::zero(),
                E::ScalarField::zero(),
            ],
        ]),
        E::pairing(pp.pps.k, pp.pps.h),
    )
}
