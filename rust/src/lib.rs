use sha2::{Sha256, Digest};
use x25519_dalek::{StaticSecret, PublicKey};
use std::convert::TryInto;

pub fn tag(ours: &StaticSecret, theirs: &PublicKey, ctr: u8, msg: &Vec<u8>) -> [u8; 32] {
  let sym_secret = ours.diffie_hellman(theirs);
  let mut hasher = Sha256::new();
  hasher.update(&sym_secret.to_bytes());
  hasher.update([ctr]);
  hasher.update(msg);
  let digest = hasher.finalize();
  digest.try_into().unwrap()
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand_core::OsRng;

  #[test]
  fn test_simple() -> Result<(), String> {
    let ours = StaticSecret::new(OsRng);
    let theirs = PublicKey::from(&ours);
    let msg: Vec<u8> = vec![255, 100];
    let _t = tag(&ours, &theirs, 0, &msg);
    // assert_eq!(sqrt(x)?.powf(2.0), x);
    Ok(())
  }
}
