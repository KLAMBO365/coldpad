use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs::OpenOptions, io};

pub const DEFAULT_STEM: &str = "output";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct PlannedWrite<'a> {
    path: &'a Path,
    contents: &'a [u8],
    secret: bool,
}

impl<'a> PlannedWrite<'a> {
    pub fn new(path: &'a Path, contents: &'a [u8], secret: bool) -> Self {
        Self {
            path,
            contents,
            secret,
        }
    }
}

fn sibling_temp_path(path: &Path, kind: &str) -> PathBuf {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(
        ".{name}.coldpad-{kind}-{}-{id}",
        std::process::id()
    ))
}

/// Stage a related set of files, then commit them as one transaction.
///
/// If a commit fails, previously existing files are restored and newly-created
/// destinations are removed.
pub fn write_files_atomically(
    writes: &[PlannedWrite<'_>],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut staged = Vec::with_capacity(writes.len());
    for write in writes {
        let temp = sibling_temp_path(write.path, "tmp");
        if let Err(error) = write_file(&temp, write.contents, false, write.secret) {
            for path in &staged {
                let _ = std::fs::remove_file(path);
            }
            return Err(error);
        }
        staged.push(temp);
    }

    if !force {
        for (write, temp) in writes.iter().zip(&staged) {
            if let Err(error) = std::fs::hard_link(temp, write.path) {
                for committed in writes.iter().take_while(|item| item.path != write.path) {
                    let _ = std::fs::remove_file(committed.path);
                }
                for path in &staged {
                    let _ = std::fs::remove_file(path);
                }
                return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                    format!(
                        "'{}' already exists (use --force to overwrite)",
                        write.path.display()
                    )
                    .into()
                } else {
                    format!("failed to write '{}': {error}", write.path.display()).into()
                });
            }
        }
        for path in &staged {
            std::fs::remove_file(path)?;
        }
        return Ok(());
    }

    let mut backups: Vec<Option<PathBuf>> = Vec::with_capacity(writes.len());
    for write in writes {
        let metadata = std::fs::symlink_metadata(write.path).ok();
        if metadata.as_ref().is_some_and(|metadata| metadata.is_dir()) {
            for (prior, saved) in writes.iter().zip(&backups) {
                if let Some(saved) = saved {
                    let _ = std::fs::rename(saved, prior.path);
                }
            }
            for path in &staged {
                let _ = std::fs::remove_file(path);
            }
            return Err(format!(
                "failed to write '{}': path is a directory",
                write.path.display()
            )
            .into());
        }
        if metadata.is_some() {
            let backup = sibling_temp_path(write.path, "backup");
            if let Err(error) = std::fs::rename(write.path, &backup) {
                for (prior, saved) in writes.iter().zip(&backups) {
                    if let Some(saved) = saved {
                        let _ = std::fs::rename(saved, prior.path);
                    }
                }
                for path in &staged {
                    let _ = std::fs::remove_file(path);
                }
                return Err(
                    format!("failed to prepare '{}': {error}", write.path.display()).into(),
                );
            }
            backups.push(Some(backup));
        } else {
            backups.push(None);
        }
    }

    for (index, (write, temp)) in writes.iter().zip(&staged).enumerate() {
        if let Err(error) = std::fs::rename(temp, write.path) {
            for committed in writes.iter().take(index) {
                let _ = std::fs::remove_file(committed.path);
            }
            for (original, backup) in writes.iter().zip(&backups) {
                if let Some(backup) = backup {
                    let _ = std::fs::rename(backup, original.path);
                }
            }
            for path in staged.iter().skip(index) {
                let _ = std::fs::remove_file(path);
            }
            return Err(format!("failed to commit '{}': {error}", write.path.display()).into());
        }
    }

    for backup in backups.into_iter().flatten() {
        if backup.is_dir() {
            std::fs::remove_dir_all(backup)?;
        } else {
            std::fs::remove_file(backup)?;
        }
    }
    Ok(())
}

pub fn read_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            format!("'{}' not found", path.display()).into()
        } else {
            format!("failed to read '{}': {e}", path.display()).into()
        }
    })
}

pub fn preflight_output_paths(
    paths: &[PathBuf],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !force {
        for path in paths {
            if path.exists() {
                return Err(format!(
                    "'{}' already exists (use --force to overwrite)",
                    path.display()
                )
                .into());
            }
        }
    }

    Ok(())
}

fn write_file(
    path: &Path,
    contents: &[u8],
    force: bool,
    secret: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    #[cfg(unix)]
    if secret {
        options.mode(0o600);
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

    #[cfg(unix)]
    if secret {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

pub fn write_output_file(
    path: &Path,
    contents: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    write_file(path, contents, force, false)
}

pub fn write_secret_file(
    path: &Path,
    contents: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    write_file(path, contents, force, true)
}

pub fn read_hash_file(hash_path: &Path) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(hash_path) {
        Ok(contents) => Ok(Some(contents.trim().to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("failed to read '{}': {e}", hash_path.display()).into()),
    }
}
