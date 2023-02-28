extern crate secp256k1;

use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn main() {
    let secp = Secp256k1::new();
    let seckey = SecretKey::new();
    let _pubkey = PublicKey::from_secret_key(&secp, &seckey);
    print!("{}", _pubkey.to_string())
}
