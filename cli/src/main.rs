use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use fips205::traits::{SerDes, Signer, Verifier};
use fips205::{slh_dsa_sha2_128f, slh_dsa_sha2_128s};

#[derive(Parser)]
#[command(name = "fips205-cli")]
#[command(about = "FIPS 205 SLH-DSA key generation and transaction signing for IOTA AA")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new SLH-DSA keypair
    Keygen {
        /// Parameter set: "128s" or "128f"
        #[arg(short, long, default_value = "128s")]
        param: String,

        /// Output directory for key files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Sign a transaction digest
    Sign {
        /// Hex-encoded transaction digest (32 bytes)
        #[arg(short, long)]
        digest: String,

        /// Path to the secret key file
        #[arg(short, long)]
        secret_key: PathBuf,

        /// Hex-encoded account address (32 bytes) used as FIPS 205 context for domain separation
        #[arg(short, long)]
        address: String,

        /// Parameter set: "128s" or "128f"
        #[arg(short, long, default_value = "128s")]
        param: String,
    },
    /// Verify a signature against a transaction digest
    Verify {
        /// Hex-encoded transaction digest (32 bytes)
        #[arg(short, long)]
        digest: String,

        /// Hex-encoded signature
        #[arg(long)]
        signature: String,

        /// Path to the public key file
        #[arg(short = 'k', long)]
        public_key: PathBuf,

        /// Hex-encoded account address (32 bytes) used as FIPS 205 context for domain separation
        #[arg(short, long)]
        address: String,

        /// Parameter set: "128s" or "128f"
        #[arg(short, long, default_value = "128s")]
        param: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { param, output } => keygen(&param, &output),
        Commands::Sign {
            digest,
            secret_key,
            address,
            param,
        } => sign(&digest, &secret_key, &address, &param),
        Commands::Verify {
            digest,
            signature,
            public_key,
            address,
            param,
        } => verify(&digest, &signature, &public_key, &address, &param),
    }
}

fn keygen(param: &str, output: &PathBuf) {
    fs::create_dir_all(output).expect("Failed to create output directory");

    let pk_path = output.join("public_key.bin");
    let sk_path = output.join("secret_key.bin");

    match param {
        "128s" => {
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("Key generation failed");
            fs::write(&pk_path, pk.into_bytes()).expect("Failed to write public key");
            fs::write(&sk_path, sk.into_bytes()).expect("Failed to write secret key");
        }
        "128f" => {
            let (pk, sk) = slh_dsa_sha2_128f::try_keygen().expect("Key generation failed");
            fs::write(&pk_path, pk.into_bytes()).expect("Failed to write public key");
            fs::write(&sk_path, sk.into_bytes()).expect("Failed to write secret key");
        }
        _ => {
            eprintln!("Error: unsupported parameter set '{param}'. Use '128s' or '128f'.");
            std::process::exit(1);
        }
    }

    println!("Keypair generated ({param}):");
    println!("  Public key:  {}", pk_path.display());
    println!("  Secret key:  {}", sk_path.display());
    println!(
        "  Public key (hex): {}",
        hex::encode(fs::read(&pk_path).unwrap())
    );
}

fn parse_hex_32(hex_str: &str, label: &str) -> [u8; 32] {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).unwrap_or_else(|_| {
        eprintln!("Error: invalid hex {label}");
        std::process::exit(1);
    });
    <[u8; 32]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
        eprintln!("Error: {label} must be exactly 32 bytes");
        std::process::exit(1);
    })
}

/// Split point for 128f signatures: R(16) + sig_fors(3696) = 3712 bytes.
/// This is the natural FORS/HT boundary used by the on-chain split signature API.
const SIG_R_FORS_LEN_128F: usize = 3712;

fn sign(digest_hex: &str, sk_path: &PathBuf, address_hex: &str, param: &str) {
    let digest = parse_hex_32(digest_hex, "digest");
    let context = parse_hex_32(address_hex, "address");
    let sk_bytes = fs::read(sk_path).expect("Failed to read secret key file");

    match param {
        "128s" => {
            let sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(
                sk_bytes.as_slice().try_into().expect("Invalid secret key length"),
            )
            .expect("Invalid secret key");
            let sig = sk.try_sign(&digest, &context, false).expect("Signing failed");
            // 128s fits in a single arg — output one line
            println!("{}", hex::encode(sig));
        }
        "128f" => {
            let sk = slh_dsa_sha2_128f::PrivateKey::try_from_bytes(
                sk_bytes.as_slice().try_into().expect("Invalid secret key length"),
            )
            .expect("Invalid secret key");
            let sig = sk.try_sign(&digest, &context, false).expect("Signing failed");
            // 128f exceeds the 16K arg limit — output two lines split at the FORS/HT boundary
            let (sig_r_fors, sig_ht) = sig.split_at(SIG_R_FORS_LEN_128F);
            println!("{}", hex::encode(sig_r_fors));
            println!("{}", hex::encode(sig_ht));
        }
        _ => {
            eprintln!("Error: unsupported parameter set '{param}'. Use '128s' or '128f'.");
            std::process::exit(1);
        }
    };
}

fn verify(digest_hex: &str, sig_hex: &str, pk_path: &PathBuf, address_hex: &str, param: &str) {
    let digest = parse_hex_32(digest_hex, "digest");
    let context = parse_hex_32(address_hex, "address");
    let sig_bytes = hex::decode(sig_hex).expect("Invalid hex signature");
    let pk_bytes = fs::read(pk_path).expect("Failed to read public key file");

    let valid = match param {
        "128s" => {
            let pk = slh_dsa_sha2_128s::PublicKey::try_from_bytes(
                pk_bytes.as_slice().try_into().expect("Invalid public key length"),
            )
            .expect("Invalid public key");
            let sig: &[u8; 7856] = sig_bytes
                .as_slice()
                .try_into()
                .expect("Invalid signature length for 128s (expected 7856 bytes)");
            pk.verify(&digest, sig, &context)
        }
        "128f" => {
            let pk = slh_dsa_sha2_128f::PublicKey::try_from_bytes(
                pk_bytes.as_slice().try_into().expect("Invalid public key length"),
            )
            .expect("Invalid public key");
            let sig: &[u8; 17088] = sig_bytes
                .as_slice()
                .try_into()
                .expect("Invalid signature length for 128f (expected 17088 bytes)");
            pk.verify(&digest, sig, &context)
        }
        _ => {
            eprintln!("Error: unsupported parameter set '{param}'. Use '128s' or '128f'.");
            std::process::exit(1);
        }
    };

    if valid {
        println!("Signature is VALID");
    } else {
        eprintln!("Signature is INVALID");
        std::process::exit(1);
    }
}
