package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var (
	encryptionKey = []byte("testkey1234567890")
	salt          = make([]byte, 16)
)

func createTempFileWithData(data []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "testfile-*.txt")
	if err != nil {
		return "", err
	}

	_, err = tmpFile.Write(data)
	if err != nil {
		return "", err
	}

	err = tmpFile.Close()
	if err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

func TestEncryptionDecryptionSingleFile(t *testing.T) {
	// Test data
	originalData := []byte("This is a test data for encryption.")
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Creating temporary file with data
	tmpFilePath, err := createTempFileWithData(originalData)
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFilePath)

	// Encrypting the file
	derivedKey := deriveKey(encryptionKey, salt)
	encryptedFilePath := tmpFilePath + ".cryptsec"

	// Encrypting the file
	if err := encryptFileGCM(tmpFilePath, derivedKey, salt, 0); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Checking if the encrypted file was created
	if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
		t.Fatalf("Encrypted file does not exist: %v", err)
	}

	// Decrypting the file
	if err := decryptFileGCM(encryptedFilePath, encryptionKey, 0, false); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Checking if the content of the file was correctly restored
	decryptedData, err := os.ReadFile(tmpFilePath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Fatalf("Decrypted data does not match original data.")
	}

	// Cleaning up temporary files
	os.Remove(encryptedFilePath)
}

func TestEncryptionDecryptionDirectory(t *testing.T) {
	// Test data
	originalData1 := []byte("File 1 data")
	originalData2 := []byte("File 2 data")
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Creating temporary directory
	tmpDir := t.TempDir()

	// Creating temporary files inside the directory
	tmpFilePath1, err := createTempFileWithData(originalData1)
	if err != nil {
		t.Fatalf("Failed to create temporary file 1: %v", err)
	}
	defer os.Remove(tmpFilePath1)

	tmpFilePath2, err := createTempFileWithData(originalData2)
	if err != nil {
		t.Fatalf("Failed to create temporary file 2: %v", err)
	}
	defer os.Remove(tmpFilePath2)

	// Moving the temporary files to the directory
	if err := os.Rename(tmpFilePath1, filepath.Join(tmpDir, "file1.txt")); err != nil {
		t.Fatalf("Failed to move file 1 to directory: %v", err)
	}
	if err := os.Rename(tmpFilePath2, filepath.Join(tmpDir, "file2.txt")); err != nil {
		t.Fatalf("Failed to move file 2 to directory: %v", err)
	}

	// Encrypting all files in the directory
	derivedKey := deriveKey(encryptionKey, salt)
	processDirectory(tmpDir, derivedKey, salt, true, false, true, 2, 0, false)

	// Checking if the encrypted files were created
	if _, err := os.Stat(filepath.Join(tmpDir, "file1.txt.cryptsec")); os.IsNotExist(err) {
		t.Fatalf("Encrypted file 1 does not exist: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "file2.txt.cryptsec")); os.IsNotExist(err) {
		t.Fatalf("Encrypted file 2 does not exist: %v", err)
	}

	// Decrypting the files in the directory
	// Building the paths for the encrypted files
	encryptedFile1 := filepath.Join(tmpDir, "file1.txt.cryptsec")
	encryptedFile2 := filepath.Join(tmpDir, "file2.txt.cryptsec")

	// Creating temporary directory for decryption
	decryptDir := t.TempDir()

	// Moving encrypted files to the temporary directory for decryption
	if err := os.Rename(encryptedFile1, filepath.Join(decryptDir, "file1.txt.cryptsec")); err != nil {
		t.Fatalf("Failed to move encrypted file 1 to decrypt directory: %v", err)
	}
	if err := os.Rename(encryptedFile2, filepath.Join(decryptDir, "file2.txt.cryptsec")); err != nil {
		t.Fatalf("Failed to move encrypted file 2 to decrypt directory: %v", err)
	}

	processDirectory(decryptDir, encryptionKey, salt, false, true, true, 2, 0, false)

	// Checking if the content of the files was correctly restored
	decryptedData1, err := os.ReadFile(filepath.Join(decryptDir, "file1.txt"))
	if err != nil {
		t.Fatalf("Failed to read decrypted file 1: %v", err)
	}

	decryptedData2, err := os.ReadFile(filepath.Join(decryptDir, "file2.txt"))
	if err != nil {
		t.Fatalf("Failed to read decrypted file 2: %v", err)
	}

	if !bytes.Equal(originalData1, decryptedData1) {
		t.Fatalf("Decrypted data 1 does not match original data.")
	}

	if !bytes.Equal(originalData2, decryptedData2) {
		t.Fatalf("Decrypted data 2 does not match original data.")
	}
}

func TestMultithreading(t *testing.T) {
	// Test data
	originalData := []byte("Test data for multiple files.")
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Creating temporary directory
	tmpDir := t.TempDir()

	// Creating multiple files in the directory
	numFiles := 5
	for i := 0; i < numFiles; i++ {
		filePath, err := createTempFileWithData(originalData)
		if err != nil {
			t.Fatalf("Failed to create temporary file: %v", err)
		}
		defer os.Remove(filePath)

		if err := os.Rename(filePath, filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))); err != nil {
			t.Fatalf("Failed to move file to directory: %v", err)
		}
	}

	// Encrypting the files with multithreading
	derivedKey := deriveKey(encryptionKey, salt)
	processDirectory(tmpDir, derivedKey, salt, true, false, true, 2, 0, false)

	// Checking if the encrypted files were created
	for i := 0; i < numFiles; i++ {
		if _, err := os.Stat(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt.cryptsec", i))); os.IsNotExist(err) {
			t.Fatalf("Encrypted file %d does not exist: %v", i, err)
		}
	}

	// Decrypting the files with multithreading
	// Creating temporary directory for decryption
	decryptDir := t.TempDir()

	// Moving encrypted files to the temporary directory for decryption
	for i := 0; i < numFiles; i++ {
		encryptedFile := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt.cryptsec", i))
		if err := os.Rename(encryptedFile, filepath.Join(decryptDir, fmt.Sprintf("file%d.txt.cryptsec", i))); err != nil {
			t.Fatalf("Failed to move encrypted file %d to decrypt directory: %v", i, err)
		}
	}

	processDirectory(decryptDir, encryptionKey, salt, false, true, true, 2, 0, false)

	// Checking if the content of the files was correctly restored
	for i := 0; i < numFiles; i++ {
		decryptedData, err := os.ReadFile(filepath.Join(decryptDir, fmt.Sprintf("file%d.txt", i)))
		if err != nil {
			t.Fatalf("Failed to read decrypted file %d: %v", i, err)
		}

		if !bytes.Equal(originalData, decryptedData) {
			t.Fatalf("Decrypted data %d does not match original data.", i)
		}
	}
}

func BenchmarkEncryption(t *testing.B) {
	originalData := []byte("Benchmarking the encryption of a file. This data will be large enough to test performance.")
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Creating temporary file
	tmpFilePath, err := createTempFileWithData(originalData)
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFilePath)

	// Encrypting
	derivedKey := deriveKey(encryptionKey, salt)
	t.ResetTimer()
	t.StartTimer()

	err = encryptFileGCM(tmpFilePath, derivedKey, salt, 0)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.StopTimer()
}
