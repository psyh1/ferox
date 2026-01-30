use std::{
    fmt,
    fs::{self, OpenOptions},
    io::Read,
    path::PathBuf,
};

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, aead::Aead};

use argon2::{Argon2, RECOMMENDED_SALT_LEN};
use chrono::{DateTime, Local};
use clap::{Args, Parser};
use rand::RngCore;

const RECOMMENDED_NONCE_LEN: usize = 12;
const RECOMMENDED_PASSWORD_LEN: usize = 32;

#[derive(Parser)]
#[command(version, author, about, long_about = None)]
pub struct FeroxCli {
    #[command(flatten)]
    pub algorithm: Cipher,
    #[arg(short, long)]
    password: Option<String>,
    #[arg(required = true)]
    pub path: Vec<String>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct Cipher {
    #[arg(short, long)]
    pub encrypt: bool,
    #[arg(short, long)]
    pub decrypt: bool,
}

// #[derive(Args)]
// struct EncryptArgs {}

// #[derive(Args)]
// struct DecryptArgs {}

#[derive(Debug, Default)]
struct Context {
    application: String,
    timestamp: DateTime<Local>,
}

#[allow(unused)]
impl Context {
    // "[application] [commit timestamp] [purpose]", e.g., "example.com 2019-12-25 16:18:03 session tokens v1"
    fn new(application: String) -> Self {
        Self {
            application,
            timestamp: Local::now(),
        }
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.application, self.timestamp)
    }
}

#[allow(unused)]
impl FeroxCli {
    fn select_dir(&self) -> anyhow::Result<String> {
        let mut dirs = Vec::<String>::new();

        if let Some(path) = dirs::home_dir() {
            fs::read_dir(path)?.for_each(|e| match e {
                Ok(entry) => {
                    let name = entry.path().to_string_lossy().to_string();
                    dirs.push(name);
                }
                Err(error) => println!("{}", error),
            });
        }

        let selected_dir = inquire::Select::new("Select directory", dirs).prompt()?;

        Ok(selected_dir)
    }

    fn select_files(&self, path: String) -> anyhow::Result<Vec<String>> {
        let path = PathBuf::from(path);

        let files: Vec<String> = fs::read_dir(&path)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        let multi_select = inquire::MultiSelect::new("Select file/s", files);

        let selected = multi_select.prompt()?;

        Ok(selected)
    }

    fn get_pass(&self) -> anyhow::Result<String> {
        let pwd = inquire::Password::new("Password").prompt()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(pwd.as_bytes());
        let res = hasher.finalize();
        Ok(res.to_hex().to_string())
    }

    fn derive_key(
        &self,
        password: &str,
        salt: [u8; RECOMMENDED_SALT_LEN],
        out: &mut [u8],
    ) -> anyhow::Result<()> {
        let argon2 = Argon2::default();

        argon2
            .hash_password_into(password.as_bytes(), &salt, out)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        Ok(())
    }

    fn gen_rand_salt(&self) -> [u8; argon2::RECOMMENDED_SALT_LEN] {
        let mut salt = [0u8; argon2::RECOMMENDED_SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        salt
    }

    fn gen_rand_nonce(&self) -> [u8; RECOMMENDED_NONCE_LEN] {
        let mut slice = [0u8; RECOMMENDED_NONCE_LEN];
        rand::rng().fill_bytes(&mut slice);
        slice
    }

    pub fn encrypt(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        // Key Deriviation
        let salt = self.gen_rand_salt();
        let mut key = [0u8; RECOMMENDED_PASSWORD_LEN];
        if let Some(pwd) = &self.password {
            self.derive_key(pwd.as_str(), salt, &mut key)?;
        } else {
            let password = self.get_pass()?;
            self.derive_key(password.as_str(), salt, &mut key);
        }

        // Initialize cipher from derived key
        let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|e| anyhow::anyhow!("{e}"))?;

        // Initialize nonce for encryption
        let slice = self.gen_rand_nonce();
        let nonce = Nonce::from_slice(&slice);

        // Read the content of the file
        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut buf = Vec::<u8>::new();
        file.read_to_end(&mut buf)?;

        // Encrypt the content of the file
        let ciphertext = cipher
            .encrypt(nonce, buf.as_ref())
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        // Assemble - format: [salt - 16] [nonce - 12] [magic length - 1] [magic - 8] [ciphertext - ..]
        let mut all = Vec::<u8>::new();
        all.extend_from_slice(&salt);
        all.extend_from_slice(nonce);
        if let Some(t) = infer::get(&buf) {
            let mime_t = t.mime_type();
            let mime_tb = mime_t.bytes();
            let magic_len = mime_tb.len() as u8;
            all.push(magic_len);
            all.extend(mime_tb);
        }
        all.extend_from_slice(&ciphertext);

        Ok(all)
    }

    pub fn decrypt(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let buf = std::fs::read(path)?;

        const SALT_LEN: usize = RECOMMENDED_SALT_LEN;
        const NONCE_LEN: usize = RECOMMENDED_NONCE_LEN;
        const MAGIC_LEN: usize = 1;

        let salt: [u8; SALT_LEN] = buf[0..SALT_LEN].try_into()?;
        let nonce: [u8; NONCE_LEN] = buf[SALT_LEN..SALT_LEN + NONCE_LEN].try_into()?;
        let magic_len: [u8; 1] = buf[SALT_LEN + NONCE_LEN..SALT_LEN + NONCE_LEN + 1].try_into()?;
        let mut magic = Vec::<u8>::with_capacity(magic_len[0] as usize);
        magic.extend_from_slice(
            &buf[SALT_LEN + NONCE_LEN + MAGIC_LEN
                ..SALT_LEN + NONCE_LEN + MAGIC_LEN + magic_len[0] as usize],
        );

        let ciphertext = buf[SALT_LEN + NONCE_LEN + MAGIC_LEN + magic_len[0] as usize..].to_vec();

        let mut key = [0u8; RECOMMENDED_PASSWORD_LEN];
        if let Some(pwd) = &self.password {
            self.derive_key(pwd.as_str(), salt, &mut key);
        } else {
            let password = self.get_pass()?;
            self.derive_key(password.as_str(), salt, &mut key);
        }
        let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|e| anyhow::anyhow!("{e}"))?;

        let nonce = Nonce::from_slice(&nonce);

        let decrypted_data = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        Ok(decrypted_data)
    }
}
