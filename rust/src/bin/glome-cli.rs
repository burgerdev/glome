use clap::{App, SubCommand};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, StaticSecret, PublicKey};

use std::io::{self, Read, Write};

fn genkey() -> io::Result<()> {
  io::stdout().write_all(&StaticSecret::new(OsRng).to_bytes())
}

fn pubkey() -> io::Result<()> {
  let mut buf: [u8; 32] = [0; 32];
  io::stdin().read_exact(&mut buf)?;
  let key = StaticSecret::from(buf);
  let pubkey = PublicKey::from(&key);
  io::stdout().write_all(&pubkey.to_bytes())
}

fn gentag() -> io::Result<()> {
  // TODO: this is placeholder code
  let alice_secret = StaticSecret::new(OsRng);

  let bob_secret = EphemeralSecret::new(OsRng);
  let bob_public = PublicKey::from(&bob_secret);

  let mut msg: Vec<u8> = Vec::new();
  io::stdin().read_to_end(&mut msg)?;
  let t = glome::tag(&alice_secret, &bob_public, 0, &msg);

  io::stdout().write_all(&t)
}

fn main() -> io::Result<()> {

  let matches = App::new("glome")
      .subcommand(SubCommand::with_name("genkey"))
      .subcommand(SubCommand::with_name("pubkey"))
      .subcommand(SubCommand::with_name("tag"))
      .get_matches();


  match matches.subcommand_name() {
      Some("genkey") => genkey()?,
      Some("pubkey") => pubkey()?,
      Some("tag") => gentag()?,
      _ => println!("other subcommand"),
  }
  Ok(())
}
