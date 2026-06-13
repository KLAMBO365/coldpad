#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs::OpenOptions, io};

pub const DEFAULT_STEM: &str = "output";

pub fn read_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            format!("'{}' not found", path.display()).into()
        } else {
            format!("failed to read '{}': {e}", path.display()).into()
        }
    })
}

pub fn prepare_output_paths(
    stem: &str,
    force: bool,
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let cipher_path = PathBuf::from(format!("{stem}.otp"));
    let key_path = PathBuf::from(format!("{stem}.otp.key"));

    if !force {
        for path in [&cipher_path, &key_path] {
            if path.exists() {
                return Err(format!(
                    "'{}' already exists (use --force to overwrite)",
                    path.display()
                )
                .into());
            }
        }
    }

    Ok((cipher_path, key_path))
}

pub fn write_output_file(
    path: &Path,
    contents: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            format!(
                "'{}' already exists (use --force to overwrite)",
                path.display()
            )
        } else {
            format!("failed to write '{}': {e}", path.display())
        }
    })?;
    file.write_all(contents)?;
    file.flush()?;
    Ok(())
}

pub fn write_secret_file(
    path: &Path,
    contents: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            format!(
                "'{}' already exists (use --force to overwrite)",
                path.display()
            )
        } else {
            format!("failed to write '{}': {e}", path.display())
        }
    })?;

    file.write_all(contents)?;
    file.flush()?;

    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(())
}

pub fn write_hash_file(
    hash_path: &Path,
    plaintext: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let hash_hex = coldpad_core::hash::compute(plaintext);
    write_output_file(hash_path, hash_hex.as_bytes(), force)
}

pub fn read_hash_file(hash_path: &Path) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(hash_path) {
        Ok(contents) => Ok(Some(contents.trim().to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("failed to read '{}': {e}", hash_path.display()).into()),
    }
}
