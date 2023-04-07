#![no_std]

use ed25519_compact::x25519::{DHOutput, PublicKey, SecretKey};
use ed25519_compact::Error;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn compute_hmac(
    secret: &DHOutput,
    from: &PublicKey,
    to: &PublicKey,
    ctr: u8,
    msg: &[u8],
) -> HmacSha256 {
    let key = [secret.as_slice(), to.as_slice(), from.as_slice()].concat();

    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(&[ctr]);
    mac.update(msg);
    mac
}

pub fn tag(ours: &SecretKey, theirs: &PublicKey, ctr: u8, msg: &[u8]) -> Result<[u8; 32], Error> {
    let secret = theirs.dh(ours)?;

    Ok(
        compute_hmac(&secret, &ours.recover_public_key()?, theirs, ctr, msg)
            .finalize()
            .into_bytes()
            .into(),
    )
}

pub fn verify(
    ours: &SecretKey,
    theirs: &PublicKey,
    ctr: u8,
    msg: &[u8],
    tag: &[u8],
) -> Result<bool, Error> {
    let secret = theirs.dh(ours)?;

    Ok(
        compute_hmac(&secret, theirs, &ours.recover_public_key()?, ctr, msg)
            .verify_truncated_left(tag)
            .is_ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::x25519::KeyPair;
    use hex_literal::hex;

    fn keypair(b: [u8; 32]) -> KeyPair {
        let sk = SecretKey::new(b);
        let pk = sk
            .recover_public_key()
            .expect("test keys should not be weak");
        let p = KeyPair { sk, pk };
        p.validate().expect("public key should match secret key");
        p
    }

    #[test]
    fn test_vector_1() {
        let a = keypair(hex!(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        ));
        let b = keypair(hex!(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        ));
        let expected = hex!("9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3");
        assert_eq!(
            tag(&a.sk, &b.pk, 0, b"The quick brown fox").unwrap(),
            expected
        );
        assert_ne!(
            tag(&b.sk, &a.pk, 0, b"The quick brown fox").unwrap(),
            expected
        );
        assert_eq!(
            verify(
                &b.sk,
                &a.pk,
                0,
                b"The quick brown fox",
                &hex!("9c44389f462d")
            ),
            Ok(true)
        );
        assert_eq!(
            verify(
                &b.sk,
                &a.pk,
                0,
                b"The quick brown fox",
                &hex!("ffeeddccbbaa")
            ),
            Ok(false)
        );
        assert_eq!(
            verify(
                &a.sk,
                &b.pk,
                0,
                b"The quick brown fox",
                &hex!("9c44389f462d")
            ),
            Ok(false)
        );
    }

    #[test]
    fn test_vector_2() {
        let a = keypair(hex!(
            "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead"
        ));
        let b = keypair(hex!(
            "b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d"
        ));
        let expected = hex!("06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277");
        assert_eq!(
            tag(&b.sk, &a.pk, 100, b"The quick brown fox").unwrap(),
            expected
        );
        assert_ne!(
            tag(&a.sk, &b.pk, 100, b"The quick brown fox").unwrap(),
            expected
        );
        assert_eq!(
            verify(
                &a.sk,
                &b.pk,
                100,
                b"The quick brown fox",
                &hex!("06476f1f314b")
            ),
            Ok(true)
        );
        assert_eq!(
            verify(
                &a.sk,
                &b.pk,
                100,
                b"The quick brown fox",
                &hex!("ffeeddccbbaa")
            ),
            Ok(false)
        );
        assert_eq!(
            verify(
                &b.sk,
                &a.pk,
                100,
                b"The quick brown fox",
                &hex!("06476f1f314b")
            ),
            Ok(false)
        );
    }
}
