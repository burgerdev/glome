use base64::{engine::general_purpose, Engine as _};
use clap::{Args, Parser, Subcommand};
use std::convert::TryInto;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Glome,
}

#[derive(Args)]
struct TagArgs {
    /// Path to secret key
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,
    /// Path to peer's public key
    #[arg(short, long, value_name = "FILE")]
    peer: PathBuf,
    /// Message counter index
    #[arg(short, long, value_name = "n")]
    counter: Option<u8>,
}

#[derive(Args)]
struct LoginArgs {
    /// Path to secret key
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,
    /// Challenge to generate a tag for
    challenge: String,
}

#[derive(Subcommand)]
enum Glome {
    /// Generate a new secret key and print it to stdout
    Genkey,
    /// Read a private key from stdin and write its public key to stdout
    Pubkey,
    /// Tag a message read from stdin
    Tag(TagArgs),
    /// Generate a tag for a GLOME-Login challenge
    Login(LoginArgs),
}

fn genkey() -> io::Result<()> {
    io::stdout().write_all(StaticSecret::random().as_bytes())
}

// TODO(burgerdev): this is the pre-0.1.0 way of writing public keys!
fn pubkey() -> io::Result<()> {
    let mut buf: [u8; 32] = [0; 32];
    io::stdin().read_exact(&mut buf)?;
    let sk: StaticSecret = buf.into();
    let pk: PublicKey = (&sk).into();
    io::stdout().write_all(pk.as_bytes())
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
    let ours: StaticSecret = read_key(&args.key).into();
    let theirs: PublicKey = read_key(&args.peer).into();
    let ctr = args.counter.unwrap_or_default();
    let mut msg = Vec::new();
    io::stdin().read_to_end(&mut msg)?;

    let t = glome::tag(&ours, &theirs, ctr, &msg);

    let encoded = general_purpose::URL_SAFE.encode(&t);

    io::stdout().write_all(encoded.as_bytes())
}

fn login(args: &LoginArgs) -> io::Result<()> {
    let ours: StaticSecret = read_key(&args.key).into();

    let challenge_start = args
        .challenge
        .find("v2/")
        .expect("challenge should have a v2/ prefix");
    let (_, challenge) = args.challenge.split_at(challenge_start + 3);
    let parts: Vec<_> = challenge.split("/").collect();
    if parts.len() != 4 || parts[3] != "" {
        panic!("unexpected format") // TODO(burgerdev): better error output
    }
    let mut handshake = general_purpose::URL_SAFE.decode(parts[0]).unwrap(); // TODO(burgerdev): return the error
    if handshake.len() < 33 {
        panic!("handshake too short") // TODO(burgerdev): better error output
    }
    let _message_tag_suffix = handshake.split_off(33);
    let raw_public_key: [u8; 32] = handshake.split_off(1).try_into().unwrap();
    let theirs: PublicKey = raw_public_key.into();
    let _prefix = handshake[0];
    // TODO(burgerdev): If prefix high bit is 0, check with own public key most significant byte.
    // TODO(burgerdev): Check message tag prefix if provided.

    let msg = [parts[1], parts[2]].join("/");

    let t = glome::tag(&ours, &theirs, 0, msg.as_bytes());

    let encoded = general_purpose::URL_SAFE.encode(&t);

    io::stdout().write_all(encoded.as_bytes())
}

fn main() -> io::Result<()> {
    // TODO(burgerdev): pass an output buffer to make implementations testable.
    match &Cli::parse().command {
        Glome::Genkey => genkey(),
        Glome::Pubkey => pubkey(),
        Glome::Tag(tag_args) => gentag(tag_args),
        Glome::Login(login_args) => login(login_args),
    }
}
