use clap::Parser;

use crate::cli::FeroxCli;

mod cli;

fn main() -> anyhow::Result<()> {
    let ferox_cli = FeroxCli::parse();

    if !ferox_cli.path.is_empty() {
        if ferox_cli.algorithm.encrypt {
            for i in &ferox_cli.path {
                let ciphertext = ferox_cli.encrypt(i.as_str())?;
                let path = std::path::PathBuf::from(i);

                if let Some(ext) = path.extension().map(|e| e.to_str().unwrap())
                    && ext != "frx"
                {
                    std::fs::write(&path, ciphertext)?;
                    let mut new_path = std::path::PathBuf::from(&path);
                    new_path.set_extension("frx");
                    std::fs::rename(path, new_path)?;
                }
            }
        }
        if ferox_cli.algorithm.decrypt {
            for i in &ferox_cli.path {
                let path = std::path::PathBuf::from(i);

                if let Some(ext) = path.extension().map(|e| e.to_str().unwrap())
                    && ext == "frx"
                {
                    let decrypted_data = ferox_cli.decrypt(i)?;

                    std::fs::write(&path, &decrypted_data)?;
                    let mut new_path = std::path::PathBuf::from(&path);
                    if let Some(t) = infer::get(&decrypted_data) {
                        new_path.set_extension(t.extension());
                    }
                    std::fs::rename(path, new_path)?;
                }
            }
        } else {
            // do nothing
        }
    }

    Ok(())
}
