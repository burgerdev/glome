use base64::{engine::general_purpose, Engine as _};
use clap::{Args, Parser, Subcommand};
use ed25519_compact::x25519::{KeyPair, PublicKey, SecretKey};
use std::convert::TryInto;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Glome,
}

#[derive(Args)]
struct TagArgs {
    /// Path to secret key
    #[arg(long, value_name = "FILE")]
    key: PathBuf,
    /// Path to peer's public key
    #[arg(long, value_name = "FILE")]
    peer: PathBuf,
}

#[derive(Subcommand)]
enum Glome {
    /// Generate a new secret key and print it to stdout
    Genkey,
    /// Read a private key from stdin and write its public key to stdout
    Pubkey,
    /// Tag a message read from stdin
    Tag(TagArgs),
}

fn genkey() -> io::Result<()> {
    let a = KeyPair::generate();
    io::stdout().write_all(&a.sk.as_slice())
}

fn pubkey() -> io::Result<()> {
    let mut buf: [u8; 32] = [0; 32];
    io::stdin().read_exact(&mut buf)?;
    let sk = SecretKey::new(buf);
    let pk = sk
        .recover_public_key()
        .expect("secret key should not be weak");
    io::stdout().write_all(&pk.as_slice())
}

fn read_key(path: &PathBuf) -> [u8; 32] {
    let b: Box<[u8; 32]> = fs::read(path)
        .expect(format!("file {:?} should be readable", path).as_str())
        .into_boxed_slice()
        .try_into()
        .expect(format!("file {:?} should contain exactly 32 bytes", path).as_str());
    *b
}

fn gentag(args: &TagArgs) -> io::Result<()> {
    let sk = SecretKey::new(read_key(&args.key));
    let pk = PublicKey::new(read_key(&args.peer));

    let t = glome::tag(&sk, &pk, 0 /* TODO */, b"" /* TODO */);

    let encoded = general_purpose::URL_SAFE.encode(&t.expect("tagging should have worked"));

    io::stdout().write_all(encoded.as_bytes())
}

fn main() -> io::Result<()> {
    match &Cli::parse().command {
        Glome::Genkey => genkey(),
        Glome::Pubkey => pubkey(),
        Glome::Tag(tag_args) => gentag(tag_args),
    }
}
