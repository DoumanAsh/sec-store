use ring::aead::{UnboundKey, LessSafeKey, Nonce, Aad, CHACHA20_POLY1305};

pub fn generate_key(salt: &[u8], pass: &[u8]) -> [u8; 32] {
    use core::num::NonZeroU32;

    const IT: NonZeroU32 = unsafe {
        NonZeroU32::new_unchecked(1_000)
    };

    use ring::pbkdf2::{self, PBKDF2_HMAC_SHA512};
    let mut out = [0u8; 32];
    pbkdf2::derive(PBKDF2_HMAC_SHA512, IT, salt, pass, &mut out);

    out
}

pub struct Manager {
    key: [u8; 32],
    //Additional security if we use it
    //Consider
    //aad: [u8; 0],
}

impl Manager {
    #[inline]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
        }
    }

    #[inline]
    fn get_nonce(&self, input: u128) -> Nonce {
        let input = input.to_ne_bytes();
        Nonce::assume_unique_for_key([
            input[0], input[1], input[2], input[3], input[4], input[5],
            input[6], input[7], input[8], input[9], input[10], input[11]
        ])
    }

    #[inline]
    fn get_aad(&self) -> Aad<impl AsRef<[u8]>> {
        Aad::empty()
    }

    pub fn encrypt<'a>(&self, nonce: u128, in_out: &'a mut Vec<u8>) -> bool {
        let key = match UnboundKey::new(&CHACHA20_POLY1305, &self.key) {
            Ok(key) => LessSafeKey::new(key),
            Err(_) => return false,
        };

        key.seal_in_place_append_tag(self.get_nonce(nonce), self.get_aad(), in_out).is_ok()
    }

    pub fn decrypt<'a>(&self, nonce: u128, in_out: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let key = match UnboundKey::new(&CHACHA20_POLY1305, &self.key) {
            Ok(key) => LessSafeKey::new(key),
            Err(_) => return None,
        };

        key.open_in_place(self.get_nonce(nonce), self.get_aad(), in_out).ok()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_encrypt_decrypt() {
        const TEXT: &[u8] = b"lolka";
        let mut value = TEXT.to_owned();

        let mut key = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 1,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 1,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 1,
            10, 20,
        ];

        let manager = Manager::new(key);
        key[0] = 0;
        let manager2 = Manager::new(key);

        assert!(manager.encrypt(1, &mut value));
        assert_ne!(value, TEXT);
        let result = manager.decrypt(1, &mut value).expect("To decrypt");
        assert_eq!(result, TEXT);
        assert!(manager.decrypt(2, &mut value).is_none());
        assert!(manager2.decrypt(1, &mut value).is_none());
    }
}
