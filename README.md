# Lockit
A tool for AES-256 encryption/decryption in GCM mode, secure file deletion by overwriting with random data, and secure wiping of encryption keys from memory.

High security for files, with secure deletion achieved by overwriting data with random patterns multiple times before removal. Encryption and decryption keys are also securely wiped from memory after use, preventing unauthorized access.


## Features

- **File Encryption**: Encrypts files using AES-GCM-256 with a user-provided key.
- **File Decryption**: Decrypts files that were encrypted using the same key.
- **Secure File Deletion**: Securely deletes files by overwriting them with random data multiple times (or using fixed patterns).
- **Directory Processing**: Encrypts, decrypts, or deletes all files in a directory with optional multithreading.
- **Key Zeroization**: Securely clears sensitive keys from memory after use to prevent potential leakage.

## Important Notice

When using the **Lockit tool** to encrypt files on Windows, **the antivirus may block the removal of the original files** after encryption. This happens because some antivirus software may flag the removal process as suspicious or potentially dangerous.

### Recommendations:
- **Check your antivirus settings**: Some antivirus programs may interfere with the removal or modification of files.
- **Temporarily disable protection**: If your antivirus is blocking the deletion of original files, consider temporarily disabling the protection or creating an exception for the tool's process.
- **Use with caution**: Ensure that the encrypted files are correctly stored before deleting the originals to avoid data loss.

This notice aims to ensure you have a smooth and secure experience when using Lockit.

## Linux Installation
```
git clone https://github.com/Sh4ngTsung/lockit.git
cd Lockit
go mod tidy
./build.sh
```

## Windows Installation
### Download the repository using PowerShell

If you prefer to avoid using Git, you can download the repository directly using PowerShell. Run the following command:
```
Invoke-WebRequest -Uri https://github.com/Sh4ngTsung/lockit/archive/refs/heads/main.zip -OutFile lockit.zip; Expand-Archive -Path lockit.zip -DestinationPath lockit; cd .\lockit\Lockit-main; .\run.bat
```

## Usage

You can run the program with the following command-line options:


### Flags

### Flags

- `-e`: Enable file encryption.
- `-d`: Enable file decryption.
- `-r <directory>`: Process all files in the specified directory.
- `-f <file>`: Process a single file.
- `-t <number of threads>`: Set the number of threads for parallel processing (only for directory processing).
- `-p <number of passes>`: Define the number of overwrite passes for secure file deletion (0 for normal deletion).
- `-c`: Display decrypted content in the terminal without modifying the original file (for decryption).
  

### Example Commands

**Encrypt a single file**:
```
lockit -e -f "file.txt"
```
**Decrypt a single file**:
```
lockit -d -f "file.txt.cryptsec"
```
**Encrypt all files in a directory**:
```
lockit -e -r "/path/to/directory"
```
**Decrypt all files in a directory**:
```
lockit -d -r "/path/to/directory"
```
**Encrypt files with multiple threads**:
```
lockit -t 8 -e -r "/path/to/directory"
```
**Display decrypted content of a file in the terminal**:
```
lockit -d -c -f "file.txt.cryptsec"
```

### Key Features

#### Key Derivation
The program uses **Argon2** to derive a 256-bit key from the user-provided password. Argon2 is a secure key derivation function designed to resist brute-force attacks and ensures the strength of the encryption key.

#### AES-GCM-256 Encryption
AES in **GCM (Galois/Counter Mode)** is used for both encryption and decryption. GCM provides both **confidentiality** (ensures data is kept secret) and **authenticity** (verifies the integrity and authenticity of the data).

#### Secure File Deletion
Files are securely deleted by overwriting them multiple times with various byte patterns (e.g., `0x00`, `0xFF`, and random data). The user can define the number of overwrite passes, making it extremely difficult for the data to be recovered after deletion.

#### Key Zeroization
After completing the encryption or decryption operation, the program **securely wipes** the keys used from memory by invoking the `zeroize()` function. This ensures that sensitive keys are not leaked or accessible after use.

#### Multithreading
The program supports **multithreaded processing** to speed up encryption, decryption, and file deletion. You can specify the number of threads to be used for parallel processing by using the `-t` flag, which is particularly useful when working with large directories or multiple files.

## Security Considerations

- **Argon2**: The key derivation process uses **Argon2**, a robust and secure hashing algorithm designed to resist brute-force and other attacks. This ensures the strength and security of the encryption key.
  
- **AES-GCM-256**: Encryption and decryption are performed using **AES in GCM mode**. GCM guarantees both **confidentiality** and **integrity** of the data, providing protection against tampering and unauthorized access.

- **Secure File Deletion**: To ensure that deleted files cannot be recovered, the tool securely overwrites them with multiple passes of random data and predefined byte patterns (e.g., `0x00`, `0xFF`). This makes it highly resistant to data recovery attempts.

- **Memory Zeroization**: After performing encryption or decryption, all sensitive keys are **securely wiped** from memory. This prevents any potential leakage of encryption keys and ensures that no trace of them remains after use.
