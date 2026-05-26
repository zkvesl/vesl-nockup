//! Tip5 permutation and `hash_varlen` sponge.
//!
//! Ported from `nockchain-math/src/tip5/`. The lookup table, round
//! constants, and MDS matrix are copied verbatim for bit-compatibility
//! with the chain-side verifier.

use crate::math::belt::{badd, bmul, mont_reduction, montify, Belt};

pub const DIGEST_LENGTH: usize = 5;
pub const STATE_SIZE: usize = 16;
pub const NUM_SPLIT_AND_LOOKUP: usize = 4;
pub const CAPACITY: usize = 6;
pub const RATE: usize = 10;
pub const NUM_ROUNDS: usize = 7;
pub const R: u128 = 18_446_744_073_709_551_616;
pub const PRIME_128: u128 = 18_446_744_069_414_584_321;

const LOOKUP_TABLE: [u8; 256] = [
    0, 7, 26, 63, 124, 215, 85, 254, 214, 228, 45, 185, 140, 173, 33, 240, 29, 177, 176, 32, 8,
    110, 87, 202, 204, 99, 150, 106, 230, 14, 235, 128, 213, 239, 212, 138, 23, 130, 208, 6, 44,
    71, 93, 116, 146, 189, 251, 81, 199, 97, 38, 28, 73, 179, 95, 84, 152, 48, 35, 119, 49, 88,
    242, 3, 148, 169, 72, 120, 62, 161, 166, 83, 175, 191, 137, 19, 100, 129, 112, 55, 221, 102,
    218, 61, 151, 237, 68, 164, 17, 147, 46, 234, 203, 216, 22, 141, 65, 57, 123, 12, 244, 54, 219,
    231, 96, 77, 180, 154, 5, 253, 133, 165, 98, 195, 205, 134, 245, 30, 9, 188, 59, 142, 186, 197,
    181, 144, 92, 31, 224, 163, 111, 74, 58, 69, 113, 196, 67, 246, 225, 10, 121, 50, 60, 157, 90,
    122, 2, 250, 101, 75, 178, 159, 24, 36, 201, 11, 243, 132, 198, 190, 114, 233, 39, 52, 21, 209,
    108, 238, 91, 187, 18, 104, 194, 37, 153, 34, 200, 143, 126, 155, 236, 118, 64, 80, 172, 89,
    94, 193, 135, 183, 86, 107, 252, 13, 167, 206, 136, 220, 207, 103, 171, 160, 76, 182, 227, 217,
    158, 56, 174, 4, 66, 109, 139, 162, 184, 211, 249, 47, 125, 232, 117, 43, 16, 42, 127, 20, 241,
    25, 149, 105, 156, 51, 53, 168, 145, 247, 223, 79, 78, 226, 15, 222, 82, 115, 70, 210, 27, 41,
    1, 170, 40, 131, 192, 229, 248, 255,
];

const ROUND_CONSTANTS: [u64; NUM_ROUNDS * STATE_SIZE] = [
    1332676891236936200,
    16607633045354064669,
    12746538998793080786,
    15240351333789289931,
    10333439796058208418,
    986873372968378050,
    153505017314310505,
    703086547770691416,
    8522628845961587962,
    1727254290898686320,
    199492491401196126,
    2969174933639985366,
    1607536590362293391,
    16971515075282501568,
    15401316942841283351,
    14178982151025681389,
    2916963588744282587,
    5474267501391258599,
    5350367839445462659,
    7436373192934779388,
    12563531800071493891,
    12265318129758141428,
    6524649031155262053,
    1388069597090660214,
    3049665785814990091,
    5225141380721656276,
    10399487208361035835,
    6576713996114457203,
    12913805829885867278,
    10299910245954679423,
    12980779960345402499,
    593670858850716490,
    12184128243723146967,
    1315341360419235257,
    9107195871057030023,
    4354141752578294067,
    8824457881527486794,
    14811586928506712910,
    7768837314956434138,
    2807636171572954860,
    9487703495117094125,
    13452575580428891895,
    14689488045617615844,
    16144091782672017853,
    15471922440568867245,
    17295382518415944107,
    15054306047726632486,
    5708955503115886019,
    9596017237020520842,
    16520851172964236909,
    8513472793890943175,
    8503326067026609602,
    9402483918549940854,
    8614816312698982446,
    7744830563717871780,
    14419404818700162041,
    8090742384565069824,
    15547662568163517559,
    17314710073626307254,
    10008393716631058961,
    14480243402290327574,
    13569194973291808551,
    10573516815088946209,
    15120483436559336219,
    3515151310595301563,
    1095382462248757907,
    5323307938514209350,
    14204542692543834582,
    12448773944668684656,
    13967843398310696452,
    14838288394107326806,
    13718313940616442191,
    15032565440414177483,
    13769903572116157488,
    17074377440395071208,
    16931086385239297738,
    8723550055169003617,
    590842605971518043,
    16642348030861036090,
    10708719298241282592,
    12766914315707517909,
    11780889552403245587,
    113183285481780712,
    9019899125655375514,
    3300264967390964820,
    12802381622653377935,
    891063765000023873,
    15939045541699412539,
    3240223189948727743,
    4087221142360949772,
    10980466041788253952,
    18199914337033135244,
    7168108392363190150,
    16860278046098150740,
    13088202265571714855,
    4712275036097525581,
    16338034078141228133,
    1455012125527134274,
    5024057780895012002,
    9289161311673217186,
    9401110072402537104,
    11919498251456187748,
    4173156070774045271,
    15647643457869530627,
    15642078237964257476,
    1405048341078324037,
    3059193199283698832,
    1605012781983592984,
    7134876918849821827,
    5796994175286958720,
    7251651436095127661,
    4565856221886323991,
];

const MDS_MATRIX_I64: [[i64; STATE_SIZE]; STATE_SIZE] = [
    [
        61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454,
        33823, 28750, 1108,
    ],
    [
        1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244,
        7454, 33823, 28750,
    ],
    [
        28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865,
        43244, 7454, 33823,
    ],
    [
        33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034,
        53865, 43244, 7454,
    ],
    [
        7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951,
        12034, 53865, 43244,
    ],
    [
        43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521,
        56951, 12034, 53865,
    ],
    [
        53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351,
        27521, 56951, 12034,
    ],
    [
        12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901,
        41351, 27521, 56951,
    ],
    [
        56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021,
        40901, 41351, 27521,
    ],
    [
        27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689,
        12021, 40901, 41351,
    ],
    [
        41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798,
        59689, 12021, 40901,
    ],
    [
        40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845,
        26798, 59689, 12021,
    ],
    [
        12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402,
        17845, 26798, 59689,
    ],
    [
        59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108,
        61402, 17845, 26798,
    ],
    [
        26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750,
        1108, 61402, 17845,
    ],
    [
        17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823,
        28750, 1108, 61402,
    ],
];

pub fn permute(sponge: &mut [u64; 16]) {
    for i in 0..NUM_ROUNDS {
        let a = sbox_layer(sponge);
        let b = linear_layer(&a);
        for j in 0..STATE_SIZE {
            let r_cons = (((ROUND_CONSTANTS[i * STATE_SIZE + j] as u128) * R) % PRIME_128) as u64;
            sponge[j] = badd(r_cons, b[j]);
        }
    }
}

fn sbox_layer(state: &[u64; STATE_SIZE]) -> [u64; STATE_SIZE] {
    let mut res = [0u64; STATE_SIZE];
    for i in 0..NUM_SPLIT_AND_LOOKUP {
        let mut bytes = state[i].to_le_bytes();
        for k in 0..8 {
            bytes[k] = LOOKUP_TABLE[bytes[k] as usize];
        }
        res[i] = u64::from_le_bytes(bytes);
    }
    for j in NUM_SPLIT_AND_LOOKUP..STATE_SIZE {
        res[j] = crate::math::belt::bpow(state[j], 7);
    }
    res
}

fn linear_layer(state: &[u64; STATE_SIZE]) -> [u64; STATE_SIZE] {
    let mut result = [0u64; STATE_SIZE];
    for i in 0..STATE_SIZE {
        for j in 0..STATE_SIZE {
            let matrix_element = MDS_MATRIX_I64[i][j] as u64;
            let product = bmul(matrix_element, state[j]);
            result[i] = badd(result[i], product);
        }
    }
    result
}

fn calc_q_r(input: &[Belt]) -> (usize, usize) {
    let n = input.len();
    (n / RATE, n % RATE)
}

fn pad(input: &mut Vec<Belt>, r: usize) {
    input.push(Belt(1));
    for _ in 0..(RATE - r) - 1 {
        input.push(Belt(0));
    }
}

fn montify_vec(input: &mut [Belt]) {
    for b in input.iter_mut() {
        *b = Belt(montify(b.0));
    }
}

fn absorb_rate(sponge: &mut [u64; 16], input: &[Belt]) {
    assert_eq!(input.len(), RATE);
    for i in 0..RATE {
        sponge[i] = input[i].0;
    }
    permute(sponge);
}

fn absorb_all(input: &[Belt], sponge: &mut [u64; 16], q: usize) {
    let mut remaining = q;
    let mut cursor = input;
    loop {
        let (head, tail) = cursor.split_at(RATE);
        absorb_rate(sponge, head);
        if remaining == 0 {
            break;
        }
        remaining -= 1;
        cursor = tail;
    }
}

fn calc_digest(sponge: &[u64; 16]) -> [u64; 5] {
    let mut digest = [0u64; DIGEST_LENGTH];
    for i in 0..DIGEST_LENGTH {
        digest[i] = mont_reduction(sponge[i] as u128);
    }
    digest
}

pub fn hash_varlen(input: &mut Vec<Belt>) -> [u64; 5] {
    // AUDIT 2026-05-25 M-34: reduce inputs to canonical form before
    // the sponge absorbs them. `Belt(pub u64)` has no validating
    // constructor, so downstream callers (vesl-core, hull-llm,
    // third-party HW wallet impls) can construct a Belt with a value
    // >= PRIME. The pre-existing `debug_assert!` is a release-mode
    // no-op; under that release path an off-field input would flow
    // through montify/mont_reduction with no normalization, producing
    // a digest the Hoon-side `atom-to-digest` (which reduces mod p)
    // cannot reproduce — the same cross-VM divergence primitive C-04
    // closed at the nockchain-tip5-rs boundary. Matching the Hoon
    // normalization here removes the footgun at the public API.
    for b in input.iter_mut() {
        if b.0 >= crate::math::belt::PRIME {
            b.0 %= crate::math::belt::PRIME;
        }
    }
    let mut sponge = [0u64; STATE_SIZE];
    for b in input.iter() {
        debug_assert!(
            crate::math::belt::based_check(b.0),
            "element must be in field"
        );
    }
    let (q, r) = calc_q_r(input);
    pad(input, r);
    montify_vec(input);
    absorb_all(input, &mut sponge, q);
    calc_digest(&sponge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_varlen_is_deterministic() {
        let mut a = vec![Belt(1), Belt(2), Belt(3)];
        let mut b = vec![Belt(1), Belt(2), Belt(3)];
        assert_eq!(hash_varlen(&mut a), hash_varlen(&mut b));
    }

    #[test]
    fn hash_varlen_differs_on_input_change() {
        let mut a = vec![Belt(1), Belt(2), Belt(3)];
        let mut b = vec![Belt(1), Belt(2), Belt(4)];
        assert_ne!(hash_varlen(&mut a), hash_varlen(&mut b));
    }
}
