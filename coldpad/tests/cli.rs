use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
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

fn coldpad_with_input(dir: &Path, args: &[&str], input: &str) -> std::process::Output {
    let mut command = coldpad();
    command
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("failed to run coldpad");
    let mut stdin = child.stdin.take().expect("failed to open child stdin");
    stdin
        .write_all(input.as_bytes())
        .expect("failed to write child stdin");
    drop(stdin);

    child
        .wait_with_output()
        .expect("failed to wait for coldpad")
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

#[test]
fn secure_encrypts_text_from_scripted_stdin() {
    let dir = temp_dir("secure-encrypt");

    let output = coldpad_with_input(
        &dir,
        &["secure"],
        "encrypt\ntext\nsecret\nsecure-out\ny\nraw\ny\n",
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("What do you want to encrypt?"));
    assert!(stderr.contains("Selection:"));
    assert!(!stderr.contains("Input source"));
    assert!(!stderr.contains("Choose 1"));
    assert!(dir.join("secure-out.otp").exists());
    assert!(dir.join("secure-out.otp.key").exists());
    assert!(dir.join("secure-out.otp.sha256").exists());

    let decrypted = coldpad()
        .current_dir(&dir)
        .args(["decrypt", "secure-out.otp"])
        .output()
        .expect("failed to run coldpad decrypt");

    assert!(
        decrypted.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
    assert_eq!(decrypted.stdout, b"secret");
}

#[test]
fn secure_aborts_when_confirmation_is_negative() {
    let dir = temp_dir("secure-abort");

    let output = coldpad_with_input(&dir, &["secure"], "keygen\n4\nabort.key\nraw\nn\n");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!dir.join("abort.key").exists());
}

#[test]
fn secure_decrypt_does_not_overwrite_existing_output_without_confirmation() {
    let dir = temp_dir("secure-decrypt-overwrite");
    let output_path = dir.join("plain.txt");

    let encrypt = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad encrypt");
    assert!(encrypt.success());

    fs::write(&output_path, b"original").expect("failed to seed output file");

    let output = coldpad_with_input(
        &dir,
        &["secure"],
        "decrypt\noutput.otp\ny\nplain.txt\nraw\nn\n",
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&output_path).expect("failed to read output file"),
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

#[cfg(unix)]
#[test]
fn secure_keygen_writes_secret_file_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("secure-key-permissions");
    let key_path = dir.join("secret.key");

    let output = coldpad_with_input(&dir, &["secure"], "keygen\n4\nsecret.key\nraw\ny\n");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mode = fs::metadata(&key_path)
        .expect("failed to stat key file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn wrap_key_requires_output() {
    let dir = temp_dir("wrap-requires-output");

    let encrypt = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad encrypt");
    assert!(encrypt.success());

    let status = coldpad()
        .current_dir(&dir)
        .args(["wrap-key", "output.otp.key", "--password", "pw"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad wrap-key");

    assert!(!status.success());
}

#[test]
fn wrap_key_and_unwrap_key_roundtrip() {
    let dir = temp_dir("wrap-roundtrip");

    let encrypt = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad encrypt");
    assert!(encrypt.success());

    let wrap = coldpad()
        .current_dir(&dir)
        .args([
            "wrap-key",
            "output.otp.key",
            "-o",
            "wrapped.otp.key",
            "--password",
            "pw",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad wrap-key");
    assert!(wrap.success());
    assert!(dir.join("wrapped.otp.key").exists());

    let unwrap = coldpad()
        .current_dir(&dir)
        .args([
            "unwrap-key",
            "wrapped.otp.key",
            "-o",
            "unwrapped.otp.key",
            "--password",
            "pw",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad unwrap-key");
    assert!(unwrap.success());

    assert_eq!(
        fs::read(dir.join("output.otp.key")).expect("failed to read original key"),
        fs::read(dir.join("unwrapped.otp.key")).expect("failed to read unwrapped key")
    );
}

#[test]
fn decrypt_with_wrapped_key_and_password() {
    let dir = temp_dir("decrypt-wrapped");

    let encrypt = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad encrypt");
    assert!(encrypt.success());

    let wrap = coldpad()
        .current_dir(&dir)
        .args([
            "wrap-key",
            "output.otp.key",
            "-o",
            "output.otp.key",
            "--password",
            "pw",
            "-f",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad wrap-key");
    assert!(wrap.success());

    let decrypt = coldpad()
        .current_dir(&dir)
        .args(["decrypt", "output.otp", "--password", "pw"])
        .output()
        .expect("failed to run coldpad decrypt");

    assert!(
        decrypt.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"secret");
}

#[test]
fn decrypt_with_wrapped_key_wrong_password_fails() {
    let dir = temp_dir("decrypt-wrapped-wrong");

    let encrypt = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad encrypt");
    assert!(encrypt.success());

    let wrap = coldpad()
        .current_dir(&dir)
        .args([
            "wrap-key",
            "output.otp.key",
            "-o",
            "output.otp.key",
            "--password",
            "pw",
            "-f",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad wrap-key");
    assert!(wrap.success());

    let decrypt = coldpad()
        .current_dir(&dir)
        .args(["decrypt", "output.otp", "--password", "wrong"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad decrypt");

    assert!(!decrypt.success());
}

#[test]
fn info_with_wrapped_key_and_password() {
    let dir = temp_dir("info-wrapped");

    let encrypt = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad encrypt");
    assert!(encrypt.success());

    let wrap = coldpad()
        .current_dir(&dir)
        .args([
            "wrap-key",
            "output.otp.key",
            "-o",
            "output.otp.key",
            "--password",
            "pw",
            "-f",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad wrap-key");
    assert!(wrap.success());

    let info = coldpad()
        .current_dir(&dir)
        .args(["info", "output.otp", "--password", "pw"])
        .output()
        .expect("failed to run coldpad info");

    assert!(
        info.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&info.stderr)
    );
    let stderr = String::from_utf8_lossy(&info.stderr);
    assert!(stderr.contains("key matches"));
}

#[cfg(unix)]
#[test]
fn wrapped_key_file_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("wrapped-key-permissions");

    let encrypt = coldpad()
        .current_dir(&dir)
        .args(["encrypt", "secret"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad encrypt");
    assert!(encrypt.success());

    let wrapped_path = dir.join("wrapped.otp.key");
    let wrap = coldpad()
        .current_dir(&dir)
        .args(["wrap-key", "output.otp.key", "-o"])
        .arg(&wrapped_path)
        .args(["--password", "pw"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run coldpad wrap-key");
    assert!(wrap.success());

    let mode = fs::metadata(&wrapped_path)
        .expect("failed to stat wrapped key file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
