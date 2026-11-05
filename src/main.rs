use clap::{Parser, Subcommand};
use secrets_vault::{derive_key, Vault};

#[derive(Parser)]
#[command(author = "Lazarus Ebi", version = "0.1.0", about = "Memory-Safe Secrets Vault")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Set {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        value: String,
        #[arg(short, long, default_value = "app.vault")]
        vault: String,
        #[arg(short, long, default_value = "default-passphrase")]
        pass: String,
    },
    Get {
        #[arg(short, long)]
        key: String,
        #[arg(short, long, default_value = "app.vault")]
        vault: String,
        #[arg(short, long, default_value = "default-passphrase")]
        pass: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Set { key, value, vault: path, pass } => {
            let salt = [0x77u8; 16];
            let k = derive_key(pass.as_bytes(), &salt)?;
            let mut vault = if std::path::Path::new(&path).exists() {
                Vault::load_from_file(&path, &k).unwrap_or_default()
            } else {
                Vault::new()
            };
            vault.insert(key.clone(), value);
            vault.save_to_file(&path, &k)?;
            println!("🔒 Secret key '{}' saved securely to {}", key, path);
        }
        Commands::Get { key, vault: path, pass } => {
            let salt = [0x77u8; 16];
            let k = derive_key(pass.as_bytes(), &salt)?;
            let vault = Vault::load_from_file(&path, &k)?;
            match vault.get(&key) {
                Some(val) => println!("🔓 Found Secret [{}]: {}", key, val),
                None => println!("❌ Key '{}' not found in vault", key),
            }
        }
    }
    Ok(())
}
