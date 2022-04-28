/*!
RC5 implementation, according to the [specification](https://www.grc.com/r&d/rc5.pdf).
*/

extern crate core;

use rand::RngCore;
use std::convert::TryInto;
use std::num::Wrapping;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Secret key representation in bytes with variable size.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    /// Create a new secret key from .
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }

    /// Create a new random secret key with the specified size.
    pub fn gen(size: u8) -> Self {
        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; size as usize];
        rng.fill_bytes(&mut key);
        Self(key)
    }
}

/// Type of words in the cipher.
pub type Word = u64;
/// Word size in bits (parameter `w`). The nominal value is 32.
const WORD_SIZE_BITS: u8 = Word::BITS as u8;

/// Inner variable and parameters of the cipher.
pub struct CipherContext {
    /// Number of rounds (parameter `r`). The nominal value is 12.
    rounds_num: u8,
    /// Secret key (parameter `K`). The nominal size is 16.
    secret_key: SecretKey,
    /// Subkey words (parameter `S`). The size is `2 * (r + 1)`.
    subkey: Zeroizing<Vec<Word>>,
}

impl Default for CipherContext {
    fn default() -> Self {
        Self::from_secret_key(SecretKey::gen(16))
    }
}

impl CipherContext {
    const BLOCK_SIZE_BYTES: usize = 2 * WORD_SIZE_BITS as usize / u8::BITS as usize;
    const SHOULD_FIT_INTO_U32_MSG: &'static str = "word size should fit in u32";
    const BLOCK_SIZE_PROOF_MSG: &'static str = "block size = 2 * word size; qed";

    /// Create a new cipher state.
    pub fn new(rounds_num: u8, secret_key: SecretKey) -> Self {
        let subkey = expand_key(&secret_key, rounds_num);
        Self {
            rounds_num,
            secret_key,
            subkey: Zeroizing::new(subkey),
        }
    }

    /// Create a new cipher state from a secret key.
    fn from_secret_key(secret_key: SecretKey) -> Self {
        let rounds_num = 12;
        Self::new(rounds_num, secret_key)
    }

    fn encode_block(&self, mut a: Word, mut b: Word) -> (Word, Word) {
        let rounds = self.rounds_num as usize;

        a = a.wrapping_add(self.subkey[0]);
        b = b.wrapping_add(self.subkey[1]);

        for i in 1..=rounds {
            let b_mod = (b % WORD_SIZE_BITS as Word)
                .try_into()
                .expect(Self::SHOULD_FIT_INTO_U32_MSG);
            a = (a ^ b).rotate_left(b_mod).wrapping_add(self.subkey[2 * i]);
            let a_mod = (a % WORD_SIZE_BITS as Word)
                .try_into()
                .expect(Self::SHOULD_FIT_INTO_U32_MSG);
            b = (b ^ a)
                .rotate_left(a_mod)
                .wrapping_add(self.subkey[2 * i + 1]);
        }
        (a, b)
    }

    fn decode_block(&self, mut a: Word, mut b: Word) -> (Word, Word) {
        let rounds = self.rounds_num as usize;
        for i in (1..=rounds).rev() {
            let a_mod = (a % WORD_SIZE_BITS as Word)
                .try_into()
                .expect(Self::SHOULD_FIT_INTO_U32_MSG);
            b = b.wrapping_sub(self.subkey[2 * i + 1]).rotate_right(a_mod) ^ a;
            let b_mod = (b % WORD_SIZE_BITS as Word)
                .try_into()
                .expect(Self::SHOULD_FIT_INTO_U32_MSG);
            a = a.wrapping_sub(self.subkey[2 * i]).rotate_right(b_mod) ^ b;
        }
        b = b.wrapping_sub(self.subkey[1]);
        a = a.wrapping_sub(self.subkey[0]);
        (a, b)
    }

    /// Encrypt a message.
    pub fn encode(&self, plaintext: [u8; Self::BLOCK_SIZE_BYTES]) -> [u8; Self::BLOCK_SIZE_BYTES] {
        let low = 0..Self::BLOCK_SIZE_BYTES / 2;
        let high = Self::BLOCK_SIZE_BYTES / 2..Self::BLOCK_SIZE_BYTES;
        let word_a = Word::from_le_bytes(
            plaintext[low.clone()]
                .try_into()
                .expect(Self::BLOCK_SIZE_PROOF_MSG),
        );
        let word_b = Word::from_le_bytes(
            plaintext[high.clone()]
                .try_into()
                .expect(Self::BLOCK_SIZE_PROOF_MSG),
        );
        let enc_words = self.encode_block(word_a, word_b);
        let mut ciphertext = [0u8; Self::BLOCK_SIZE_BYTES];
        ciphertext[low].copy_from_slice(&enc_words.0.to_le_bytes());
        ciphertext[high].copy_from_slice(&enc_words.1.to_le_bytes());
        ciphertext
    }

    /// Decrypt a message.
    pub fn decode(&self, ciphertext: [u8; Self::BLOCK_SIZE_BYTES]) -> [u8; Self::BLOCK_SIZE_BYTES] {
        let low = 0..Self::BLOCK_SIZE_BYTES / 2;
        let high = Self::BLOCK_SIZE_BYTES / 2..Self::BLOCK_SIZE_BYTES;
        let word_a = Word::from_le_bytes(ciphertext[low.clone()].try_into().unwrap());
        let word_b = Word::from_le_bytes(ciphertext[high.clone()].try_into().unwrap());
        let enc_words = self.decode_block(word_a, word_b);
        let mut plaintext = [0u8; Self::BLOCK_SIZE_BYTES];
        plaintext[low].copy_from_slice(&enc_words.0.to_le_bytes());
        plaintext[high].copy_from_slice(&enc_words.1.to_le_bytes());
        plaintext
    }

    /// Magic constants P and Q defined as: `Odd((e - 2) * (2 ** w))` and `Odd((φ - 1) * (2 ** w))`,
    /// correspondingly.
    #[allow(overflowing_literals, clippy::unnecessary_cast)]
    const fn pq() -> (Wrapping<Word>, Wrapping<Word>) {
        match WORD_SIZE_BITS as usize {
            16 => (Wrapping(0xb7e1 as Word), Wrapping(0x9e37 as Word)),
            32 => (Wrapping(0xb7e15163 as Word), Wrapping(0x9e3779b9 as Word)),
            64 => (
                Wrapping(0xb7e151628aed2a6b as Word),
                Wrapping(0x9e3779b97f4a7c15 as Word),
            ),
            _ => panic!("word size is not supported"),
        }
    }

    pub fn rounds_num(&self) -> u8 {
        self.rounds_num
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

/// Expands the user's secret key to fill the expanded array of random binary words determined by
/// the secret key.
fn expand_key(key: &SecretKey, rounds_num: u8) -> Vec<Word> {
    // Convert the secret key to words (L).
    let key_ken = key.0.len();
    let word_size_bytes = (WORD_SIZE_BITS / u8::BITS as u8) as usize;
    let key_words_len = (key_ken.max(1) + word_size_bytes - 1) / word_size_bytes;
    let mut key_words = vec![Wrapping(0); key_words_len];
    for i in (0..key_ken).rev() {
        let j = i / word_size_bytes;
        key_words[j] = (key_words[j] << 8) + Wrapping(key.0[i] as Word);
    }

    // Initialize subkey array (S) using an arithmetic progression
    // determined by the "magic constants" P and Q.
    let subkey_len = 2 * (rounds_num + 1) as usize;
    let (p, q) = CipherContext::pq();
    let mut subkey = (0..subkey_len)
        .scan(p, |s, i| {
            let x = if i == 0 { Wrapping(0) } else { q };
            *s += x;
            Some(*s)
        })
        .collect::<Vec<_>>();

    // Mix the secret key over the subkey and words of the key.
    let mut word_a = Wrapping(0);
    let mut word_b = Wrapping(0);
    let mut i = 0;
    let mut j = 0;
    for _ in 0..(3 * subkey_len.max(key_words_len)) {
        word_a = Wrapping((subkey[i] + word_a + word_b).0.rotate_left(3));
        subkey[i] = word_a;
        let ab_mod = ((word_a + word_b).0 % WORD_SIZE_BITS as Word)
            .try_into()
            .expect(CipherContext::SHOULD_FIT_INTO_U32_MSG);
        word_b = Wrapping((key_words[j] + word_a + word_b).0.rotate_left(ab_mod));
        key_words[j] = word_b;
        i = (i + 1) % subkey_len;
        j = (j + 1) % key_words_len;
    }
    // Should be eliminated by the compiler
    subkey.into_iter().map(|x| x.0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CipherContext, SecretKey};

    use std::convert::TryInto;

    fn encode(key: SecretKey, rounds_num: u8, plaintext: Vec<u8>) -> Vec<u8> {
        let state = CipherContext::new(rounds_num, key);
        let err = format!(
            "Invalid message size: {} != {}",
            plaintext.len(),
            CipherContext::BLOCK_SIZE_BYTES
        );
        let ciphertext = state.encode(plaintext.try_into().expect(&err));
        ciphertext.to_vec()
    }

    fn decode(key: SecretKey, rounds_num: u8, ciphertext: Vec<u8>) -> Vec<u8> {
        let state = CipherContext::new(rounds_num, key);
        let err = format!(
            "Invalid message size: {} != {}",
            ciphertext.len(),
            CipherContext::BLOCK_SIZE_BYTES
        );
        let plaintext = state.decode(ciphertext.try_into().expect(&err));
        plaintext.to_vec()
    }

    mod word_size_32 {
        use super::*;
        const SIZE: u8 = 32;

        #[test]
        fn encode_a() {
            if WORD_SIZE_BITS != SIZE {
                return;
            }

            let key = SecretKey(vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ]);
            let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
            let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
            let res = encode(key, 12, pt);
            assert_eq!(res, ct);
        }

        #[test]
        fn encode_b() {
            if WORD_SIZE_BITS != SIZE {
                return;
            }

            let key = SecretKey(vec![
                0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
                0xFF, 0x48,
            ]);
            let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
            let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
            let res = encode(key, 12, pt);
            assert_eq!(res, ct);
        }

        #[test]
        fn decode_a() {
            if WORD_SIZE_BITS != SIZE {
                return;
            }

            let key = SecretKey(vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ]);
            let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
            let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
            let res = decode(key, 12, ct);
            assert_eq!(res, pt);
        }

        #[test]
        fn decode_b() {
            if WORD_SIZE_BITS != SIZE {
                return;
            }

            let key = SecretKey(vec![
                0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
                0xFF, 0x48,
            ]);
            let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
            let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
            let res = decode(key, 12, ct);
            assert_eq!(res, pt);
        }
    }

    mod word_size_16 {
        use super::*;
        use hex_literal::hex;
        const SIZE: u8 = 16;

        #[test]
        fn encode_a() {
            if WORD_SIZE_BITS != SIZE {
                return;
            }

            let key = SecretKey(hex!("0001020304050607").to_vec());
            let pt = hex!("00010203").to_vec();
            let ct = hex!("23A8D72E").to_vec();
            let res = encode(key, 16, pt);
            assert_eq!(res, ct);
        }

        #[test]
        fn decode_a() {
            if WORD_SIZE_BITS != SIZE {
                return;
            }

            let key = SecretKey(hex!("0001020304050607").to_vec());
            let ct = hex!("23A8D72E").to_vec();
            let pt = hex!("00010203").to_vec();
            let res = decode(key, 16, ct);
            assert_eq!(res, pt);
        }
    }

    mod word_size_64 {
        use super::*;
        use hex_literal::hex;
        const SIZE: u8 = 64;

        #[test]
        fn encode_a() {
            if WORD_SIZE_BITS != SIZE {
                return;
            }

            let key = SecretKey(hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec());
            let pt = hex!("000102030405060708090A0B0C0D0E0F").to_vec();
            let ct = hex!("A46772820EDBCE0235ABEA32AE7178DA").to_vec();
            let res = encode(key, 24, pt);
            assert_eq!(res, ct);
        }

        #[test]
        fn decode_a() {
            if WORD_SIZE_BITS != SIZE {
                return;
            }

            let key = SecretKey(hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec());
            let ct = hex!("A46772820EDBCE0235ABEA32AE7178DA").to_vec();
            let pt = hex!("000102030405060708090A0B0C0D0E0F").to_vec();
            let res = decode(key, 24, ct);
            assert_eq!(res, pt);
        }
    }
}
