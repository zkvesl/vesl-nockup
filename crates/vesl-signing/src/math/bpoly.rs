//! Minimal Belt-polynomial operations needed for `F6lt` inversion.
//!
//! Ported from `nockchain-math/src/bpoly.rs`. Only the extended GCD path
//! (and its helpers) is retained — the full polynomial stack (FFT, coset
//! words, Hadamard, etc.) is unused by Cheetah curve arithmetic.

use crate::math::belt::Belt;

#[inline]
fn degree(p: &[Belt]) -> u32 {
    p.iter().rposition(|x| !x.is_zero()).map_or(0, |i| i as u32)
}

#[inline]
fn is_zero(p: &[Belt]) -> bool {
    p.iter().all(|x| x.is_zero())
}

pub fn bpmul(a: &[Belt], b: &[Belt], res: &mut [Belt]) {
    if is_zero(a) || is_zero(b) {
        res.fill(Belt(0));
        return;
    }
    res.fill(Belt(0));
    for i in 0..a.len() {
        if a[i].is_zero() {
            continue;
        }
        for j in 0..b.len() {
            res[i + j] = res[i + j] + a[i] * b[j];
        }
    }
}

pub fn bpsub(a: &[Belt], b: &[Belt], res: &mut [Belt]) {
    let a_len = a.len();
    let b_len = b.len();
    let res_len = a_len.max(b_len);
    for i in 0..res_len {
        if i < a_len && i < b_len {
            res[i] = a[i] - b[i];
        } else if i < a_len {
            res[i] = a[i];
        } else {
            res[i] = -b[i];
        }
    }
}

pub fn bpscal(scalar: Belt, b: &[Belt], res: &mut [Belt]) {
    for (r, bp) in res.iter_mut().zip(b.iter()) {
        *r = scalar * *bp;
    }
}

pub fn bpdvr(a: &[Belt], b: &[Belt], q: &mut [Belt], res: &mut [Belt]) {
    if is_zero(a) {
        q.fill(Belt(0));
        res.fill(Belt(0));
        return;
    }
    assert!(!is_zero(b), "divide by zero");
    q.fill(Belt(0));
    res.fill(Belt(0));

    let a_end = degree(a) as usize;
    let mut r = a[0..=a_end].to_vec();
    let deg_b = degree(b);
    let end_b = deg_b as usize;
    let mut i = a_end;
    let mut deg_r = degree(a);
    let mut q_index = deg_r.saturating_sub(deg_b);

    while deg_r >= deg_b {
        let coeff = r[i] * b[end_b].inv();
        q[q_index as usize] = coeff;
        for k in 0..=deg_b {
            let index = k as usize;
            if k <= a_end as u32 && k < b.len() as u32 && k <= i as u32 {
                r[i - index] = r[i - index] - coeff * b[end_b - index];
            }
        }
        deg_r = deg_r.saturating_sub(1);
        q_index = q_index.saturating_sub(1);
        if deg_r == 0 && r[0].is_zero() {
            break;
        }
        i -= 1;
    }

    let r_len = (deg_r + 1) as usize;
    res[..r_len].copy_from_slice(&r[..r_len]);
}

/// Extended Euclidean algorithm for Belt polynomials.
///
/// On return: `u*a + v*b = d`.
pub fn bpegcd(a: &[Belt], b: &[Belt], d: &mut [Belt], u: &mut [Belt], v: &mut [Belt]) {
    let mut m1_u = vec![Belt(0)];
    let mut m2_u = vec![Belt(1)];
    let mut m1_v = vec![Belt(1)];
    let mut m2_v = vec![Belt(0)];

    d.fill(Belt(0));
    u.fill(Belt(0));
    v.fill(Belt(0));

    let mut a = a.to_vec();
    let mut b = b.to_vec();

    while !is_zero(&b) {
        let deg_a = degree(&a);
        let deg_b = degree(&b);
        let deg_q = deg_a.saturating_sub(deg_b);
        let len_q = (deg_q + 1) as usize;
        let len_r = (deg_b + 1) as usize;

        let mut q = vec![Belt(0); len_q];
        let mut r = vec![Belt(0); len_r];
        bpdvr(&a, &b, &mut q, &mut r);

        a = b;
        b = r;

        let q_len = q.len();
        let m1_u_len = m1_u.len();
        let mut res1 = vec![Belt(0); q_len + m1_u_len - 1];
        bpmul(&q, &m1_u, &mut res1);

        let m2_u_len = m2_u.len();
        let mut res2 = vec![Belt(0); m2_u_len.max(res1.len())];
        bpsub(&m2_u, &res1, &mut res2);

        m2_u = m1_u;
        m1_u = res2;

        let m1_v_len = m1_v.len();
        let mut res1v = vec![Belt(0); q_len + m1_v_len - 1];
        bpmul(&q, &m1_v, &mut res1v);

        let m2_v_len = m2_v.len();
        let mut res3 = vec![Belt(0); m2_v_len.max(res1v.len())];
        bpsub(&m2_v, &res1v, &mut res3);

        m2_v = m1_v;
        m1_v = res3;
    }

    let a_len = a.len().min(d.len());
    d[..a_len].copy_from_slice(&a[..a_len]);

    let m2_u_len = m2_u.len().min(u.len());
    u[..m2_u_len].copy_from_slice(&m2_u[..m2_u_len]);

    let m2_v_len = m2_v.len().min(v.len());
    v[..m2_v_len].copy_from_slice(&m2_v[..m2_v_len]);
}
