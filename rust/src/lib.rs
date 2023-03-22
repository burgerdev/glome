use sha2::Sha256;
use hmac::{Hmac, Mac, digest::MacError};
use x25519_dalek::{StaticSecret, PublicKey, SharedSecret};

type HmacSha256 = Hmac<Sha256>;

fn compute_hmac(secret: &SharedSecret, from: &PublicKey, to: &PublicKey, ctr: u8, msg: &[u8]) -> HmacSha256 {
  let key = [secret.to_bytes(), to.to_bytes(), from.to_bytes()].concat();

  let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
  mac.update(&[ctr]);
  mac.update(msg);
  mac
}

pub fn tag(ours: &StaticSecret, theirs: &PublicKey, ctr: u8, msg: &[u8]) -> [u8; 32] {
  let secret = ours.diffie_hellman(theirs);

  compute_hmac(&secret, &PublicKey::from(ours), theirs, ctr, msg)
    .finalize().into_bytes().into()
}

pub fn verify(ours: &StaticSecret, theirs: &PublicKey, ctr: u8, msg: &[u8], tag: &[u8]) -> Result<(), MacError> {
  let secret = ours.diffie_hellman(theirs);

  compute_hmac(&secret, theirs, &PublicKey::from(ours), ctr, msg)
    .verify_truncated_left(tag)
}

#[cfg(test)]
mod tests {
  use super::*;
  use hex_literal::hex;

  #[test]
  fn test_vector_1() -> Result<(), MacError> {
    let k_a = StaticSecret::from(hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    let k_b = StaticSecret::from(hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    let expected = hex!("9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3");
    assert_eq!(tag(&k_a, &PublicKey::from(&k_b), 0, b"The quick brown fox"), expected);
    assert_ne!(tag(&k_b, &PublicKey::from(&k_a), 0, b"The quick brown fox"), expected);
    verify(&k_b, &PublicKey::from(&k_a), 0, b"The quick brown fox", &hex!("9c44389f462d"))
  }

  #[test]
  fn test_vector_2() -> Result<(), MacError> {
    let k_a = StaticSecret::from(hex!("fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead"));
    let k_b = StaticSecret::from(hex!("b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d"));
    let expected = hex!("06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277");
    assert_eq!(tag(&k_b, &PublicKey::from(&k_a), 100, b"The quick brown fox"), expected);
    assert_ne!(tag(&k_a, &PublicKey::from(&k_b), 100, b"The quick brown fox"), expected);
    assert!(verify(&k_a, &PublicKey::from(&k_b), 100, b"The quick brown fox", &hex!("06476f1f314b")).is_ok());
    verify(&k_a, &PublicKey::from(&k_b), 100, b"The quick brown fox", &hex!("06476f1f314b"))
  }
}
