use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn coldpad() -> Command {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_coldpad"));
    let exe = if exe.is_absolute() {
        exe
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(exe)
    };
    Command::new(exe)
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("coldpad-{name}-{nanos}"));
    fs::create_dir(&dir).expect("failed to create temp dir");
    dir
}

#[test]
fn encrypt_rejects_text_and_file_together() {
    let dir = temp_dir("conflict");
    let input = dir.join("input.txt");
    fs::write(&input, b"from-file").expect("failed to write input");

    let status = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "from-arg", "--file"])
        .arg(&input)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad");

    assert!(!status.success());
}

#[test]
fn failed_hashed_decrypt_does_not_overwrite_output_file() {
    let dir = temp_dir("decrypt-output");
    let output = dir.join("plain.txt");

    let encrypt = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "--hash", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad encrypt");
    assert!(encrypt.success());

    fs::write(dir.join("output.otp.key"), b"000000").expect("failed to corrupt key");
    fs::write(&output, b"original").expect("failed to seed output file");

    let decrypt = coldpad()
        .current_dir(&dir)
        .args(["decrypt", "output.otp", "-o"])
        .arg(&output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad decrypt");

    assert!(!decrypt.success());
    assert_eq!(
        fs::read(&output).expect("failed to read output file"),
        b"original"
    );
}

#[cfg(unix)]
#[test]
fn keygen_writes_secret_file_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("key-permissions");
    let key_path = dir.join("secret.key");

    let status = coldpad()
        .current_dir(&dir)
        .args(["keygen", "-l", "4", "-o"])
        .arg(&key_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad keygen");

    assert!(status.success());
    let mode = fs::metadata(&key_path)
        .expect("failed to stat key file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
