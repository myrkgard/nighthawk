//#![deny(warnings)]
#![warn(missing_docs)]
//! Provides encryption / decryption with ChaCha20 algorithm.

/// Encrypt / decrypt.
///
/// Arguments:
/// * `key`: Encryption / decryption key
/// * `nonce`: Nonce used for this encryption / decryption operation.
/// * `msg`: Bytes to be encrypted / decrypted
///
/// Returns:
/// * encrypted / decrypted bytes with same length as `msg` argument.
pub fn crypt(key: &Key, nonce: &Nonce, msg: &Vec<u8>) -> Vec<u8> {
    chacha20_encrypt(key, 0, nonce, msg)
}

fn chacha20_encrypt(key: &Key, counter: u32, nonce: &Nonce, plaintext: &Vec<u8>) -> Vec<u8> {
    assert!(plaintext.len() as u64 <= 2u64.pow(32) * 64);
    let mut res: Vec<u8> = Vec::with_capacity(plaintext.len());
    for j in 0..plaintext.len() / 64 {
        let key_stream = chacha20_block(key, counter + (j as u32), nonce);
        for i in 0..64 as usize {
            res.push(plaintext[j * 64 + i] ^ key_stream[i]);
        }
    }
    if (plaintext.len() % 64) != 0 {
        let j = plaintext.len() / 64;
        let key_stream = chacha20_block(key, counter + (j as u32), nonce);
        for i in 0..plaintext.len() % 64 {
            res.push(plaintext[j * 64 + i] ^ key_stream[i]);
        }
    }
    res
}

fn chacha20_block(key: &Key, counter: u32, nonce: &Nonce) -> Vec<u8> {
    let mut state = State::from_key_counter_nonce(key, counter, nonce);
    let initial_state = state.clone();
    for _i in 0..10 {
        state.inner_block();
    }
    state.add(&initial_state);
    state.serialize()
}

/// Holds 256-bit encryption / decryption key.
pub struct Key {
    data: [u32; 8],
}

impl Key {
    /// New [`Key`] from 32 bytes.
    ///
    /// Arguments:
    /// * `data`: Must be 32 bytes, panics otherwise.
    pub fn from_vector(data: &Vec<u8>) -> Self {
        assert_eq!(data.len(), 32);
        Key {
            data: [
                (data[0] as u32)
                    | (data[1] as u32) << 8
                    | (data[2] as u32) << 16
                    | (data[3] as u32) << 24,
                (data[4] as u32)
                    | (data[5] as u32) << 8
                    | (data[6] as u32) << 16
                    | (data[7] as u32) << 24,
                (data[8] as u32)
                    | (data[9] as u32) << 8
                    | (data[10] as u32) << 16
                    | (data[11] as u32) << 24,
                (data[12] as u32)
                    | (data[13] as u32) << 8
                    | (data[14] as u32) << 16
                    | (data[15] as u32) << 24,
                (data[16] as u32)
                    | (data[17] as u32) << 8
                    | (data[18] as u32) << 16
                    | (data[19] as u32) << 24,
                (data[20] as u32)
                    | (data[21] as u32) << 8
                    | (data[22] as u32) << 16
                    | (data[23] as u32) << 24,
                (data[24] as u32)
                    | (data[25] as u32) << 8
                    | (data[26] as u32) << 16
                    | (data[27] as u32) << 24,
                (data[28] as u32)
                    | (data[29] as u32) << 8
                    | (data[30] as u32) << 16
                    | (data[31] as u32) << 24,
            ],
        }
    }
}

/// Holds 96-bit nonce.
pub struct Nonce {
    data: [u32; 3],
}

impl Nonce {
    /// New [`Nonce`] from 12 bytes.
    ///
    /// Arguments:
    /// * `data`: Must be 12 bytes, panics otherwise.
    pub fn from_vector(data: &Vec<u8>) -> Self {
        assert_eq!(data.len(), 12);
        Nonce {
            data: [
                (data[0] as u32)
                    | (data[1] as u32) << 8
                    | (data[2] as u32) << 16
                    | (data[3] as u32) << 24,
                (data[4] as u32)
                    | (data[5] as u32) << 8
                    | (data[6] as u32) << 16
                    | (data[7] as u32) << 24,
                (data[8] as u32)
                    | (data[9] as u32) << 8
                    | (data[10] as u32) << 16
                    | (data[11] as u32) << 24,
            ],
        }
    }
}

#[derive(Clone)]
struct State {
    data: [u32; 16],
}

impl State {
    fn from_key_counter_nonce(key: &Key, counter: u32, nonce: &Nonce) -> Self {
        State {
            data: [
                0x61707865,
                0x3320646e,
                0x79622d32,
                0x6b206574,
                key.data[0],
                key.data[1],
                key.data[2],
                key.data[3],
                key.data[4],
                key.data[5],
                key.data[6],
                key.data[7],
                counter,
                nonce.data[0],
                nonce.data[1],
                nonce.data[2],
            ],
        }
    }

    fn add(&mut self, other: &State) {
        for i in 0..self.data.len() {
            self.data[i] = self.data[i].wrapping_add(other.data[i]);
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(64);
        for d in self.data {
            res.push(d as u8);
            res.push((d >> 8) as u8);
            res.push((d >> 16) as u8);
            res.push((d >> 24) as u8);
        }
        res
    }

    fn inner_block(&mut self) {
        self.quarter_round(0, 4, 8, 12);
        self.quarter_round(1, 5, 9, 13);
        self.quarter_round(2, 6, 10, 14);
        self.quarter_round(3, 7, 11, 15);
        self.quarter_round(0, 5, 10, 15);
        self.quarter_round(1, 6, 11, 12);
        self.quarter_round(2, 7, 8, 13);
        self.quarter_round(3, 4, 9, 14);
    }

    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        self.data[a] = self.data[a].wrapping_add(self.data[b]);
        self.data[d] ^= self.data[a];
        self.data[d] = self.data[d].rotate_left(16);
        self.data[c] = self.data[c].wrapping_add(self.data[d]);
        self.data[b] ^= self.data[c];
        self.data[b] = self.data[b].rotate_left(12);
        self.data[a] = self.data[a].wrapping_add(self.data[b]);
        self.data[d] ^= self.data[a];
        self.data[d] = self.data[d].rotate_left(8);
        self.data[c] = self.data[c].wrapping_add(self.data[d]);
        self.data[b] ^= self.data[c];
        self.data[b] = self.data[b].rotate_left(7);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_key() -> Key {
        let v: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        Key::from_vector(&v)
    }

    #[test]
    fn t_key() {
        assert_eq!(
            get_test_key().data,
            [
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
                0x1f1e1d1c
            ]
        );
    }

    fn get_test_nonce0() -> Nonce {
        let v: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        Nonce::from_vector(&v)
    }

    fn get_test_nonce1() -> Nonce {
        let v: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        Nonce::from_vector(&v)
    }

    #[test]
    fn t_nonce() {
        assert_eq!(get_test_nonce0().data, [0x09000000, 0x4a000000, 0x00000000]);
        assert_eq!(get_test_nonce1().data, [0x00000000, 0x4a000000, 0x00000000]);
    }

    fn get_test_plaintext_bytes() -> Vec<u8> {
        vec![
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ]
    }

    fn get_test_encrypted_message_bytes() -> Vec<u8> {
        vec![
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ]
    }

    #[test]
    fn t_state() {
        assert_eq!(
            State::from_key_counter_nonce(&get_test_key(), 1, &get_test_nonce0()).data,
            [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
                0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
                0x4a000000, 0x00000000,
            ]
        );
    }

    #[test]
    fn t_quarter_round() {
        let mut state = State {
            data: [
                0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
                0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
                0x2098d9d6, 0x91dbd320,
            ],
        };
        state.quarter_round(2, 7, 8, 13);
        assert_eq!(
            state.data,
            [
                0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
                0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
                0x2098d9d6, 0x91dbd320,
            ]
        );
    }

    #[test]
    fn t_chacha20_block() {
        assert_eq!(
            chacha20_block(&get_test_key(), 1, &get_test_nonce0()),
            vec!(
                0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
                0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
                0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
                0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
            )
        );
    }

    #[test]
    fn t_chacha20_encrypt() {
        assert_eq!(
            chacha20_encrypt(
                &get_test_key(),
                1,
                &get_test_nonce1(),
                &get_test_plaintext_bytes()
            ),
            get_test_encrypted_message_bytes()
        );
    }

    #[test]
    fn t_chacha20_decrypt() {
        assert_eq!(
            chacha20_encrypt(
                &get_test_key(),
                1,
                &get_test_nonce1(),
                &get_test_encrypted_message_bytes()
            ),
            get_test_plaintext_bytes()
        );
    }

    #[test]
    fn t_crypt() {
        let key = Key::from_vector(&vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let nonce = Nonce::from_vector(&vec![
            0x12, 0xaa, 0x89, 0xc9, 0xac, 0xfd, 0x38, 0x4a, 0x99, 0x00, 0xe2, 0x01,
        ]);
        let msg: Vec<u8> = vec![0x00, 0x11, 0x22, 0x33];

        let encrypted_msg = crypt(&key, &nonce, &msg);
        let decrypted_msg = crypt(&key, &nonce, &encrypted_msg);

        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn t_crypt2() {
        let key = get_test_key();
        let nonce = get_test_nonce1();
        let msg = get_test_plaintext_bytes();
        let encrypted_msg = crypt(&key, &nonce, &msg);
        let decrypted_msg = crypt(&key, &nonce, &encrypted_msg);
        assert_eq!(msg, decrypted_msg);
    }
}
