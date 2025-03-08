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

func init() {
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("Failed to generate salt: %v", err))
	}
}

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
	originalData := []byte("This is a test data for encryption.")
	tmpFilePath, err := createTempFileWithData(originalData)
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFilePath)

	derivedKey := deriveKey(encryptionKey, salt)
	encryptedFilePath := tmpFilePath + ".cryptsec"

	if err := encryptFileGCM(tmpFilePath, derivedKey, salt, 0); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
		t.Fatalf("Encrypted file does not exist: %v", err)
	}

	if err := decryptFileGCM(encryptedFilePath, encryptionKey, 0, false); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	decryptedData, err := os.ReadFile(tmpFilePath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Fatalf("Decrypted data does not match original data.")
	}

	os.Remove(encryptedFilePath)
}

func TestEncryptionDecryptionDirectory(t *testing.T) {
	originalData1 := []byte("File 1 data")
	originalData2 := []byte("File 2 data")
	tmpDir := t.TempDir()

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

	if err := os.Rename(tmpFilePath1, filepath.Join(tmpDir, "file1.txt")); err != nil {
		t.Fatalf("Failed to move file 1 to directory: %v", err)
	}
	if err := os.Rename(tmpFilePath2, filepath.Join(tmpDir, "file2.txt")); err != nil {
		t.Fatalf("Failed to move file 2 to directory: %v", err)
	}

	derivedKey := deriveKey(encryptionKey, salt)

	var files []string
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Error walking directory: %v", err)
	}

	config := Config{Encrypt: true, Decrypt: false, Threads: 2}
	processDirectory(files, derivedKey, salt, config, false)

	if _, err := os.Stat(filepath.Join(tmpDir, "file1.txt.cryptsec")); os.IsNotExist(err) {
		t.Fatalf("Encrypted file 1 does not exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "file2.txt.cryptsec")); os.IsNotExist(err) {
		t.Fatalf("Encrypted file 2 does not exist: %v", err)
	}

	encryptedFile1 := filepath.Join(tmpDir, "file1.txt.cryptsec")
	encryptedFile2 := filepath.Join(tmpDir, "file2.txt.cryptsec")
	decryptDir := t.TempDir()

	if err := os.Rename(encryptedFile1, filepath.Join(decryptDir, "file1.txt.cryptsec")); err != nil {
		t.Fatalf("Failed to move encrypted file 1 to decrypt directory: %v", err)
	}
	if err := os.Rename(encryptedFile2, filepath.Join(decryptDir, "file2.txt.cryptsec")); err != nil {
		t.Fatalf("Failed to move encrypted file 2 to decrypt directory: %v", err)
	}

	var decryptFiles []string
	err = filepath.Walk(decryptDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			decryptFiles = append(decryptFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Error walking decrypt directory: %v", err)
	}

	config = Config{Encrypt: false, Decrypt: true, Threads: 2}
	processDirectory(decryptFiles, encryptionKey, salt, config, false)

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
	originalData := []byte("Test data for multiple files.")
	tmpDir := t.TempDir()

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

	derivedKey := deriveKey(encryptionKey, salt)

	var files []string
	err := filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Error walking directory: %v", err)
	}

	config := Config{Encrypt: true, Decrypt: false, Threads: 2}
	processDirectory(files, derivedKey, salt, config, false)

	for i := 0; i < numFiles; i++ {
		if _, err := os.Stat(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt.cryptsec", i))); os.IsNotExist(err) {
			t.Fatalf("Encrypted file %d does not exist: %v", i, err)
		}
	}

	decryptDir := t.TempDir()

	for i := 0; i < numFiles; i++ {
		encryptedFile := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt.cryptsec", i))
		if err := os.Rename(encryptedFile, filepath.Join(decryptDir, fmt.Sprintf("file%d.txt.cryptsec", i))); err != nil {
			t.Fatalf("Failed to move encrypted file %d to decrypt directory: %v", i, err)
		}
	}

	var decryptFiles []string
	err = filepath.Walk(decryptDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			decryptFiles = append(decryptFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Error walking decrypt directory: %v", err)
	}

	config = Config{Encrypt: false, Decrypt: true, Threads: 2}
	processDirectory(decryptFiles, encryptionKey, salt, config, false)

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

func BenchmarkEncryption(b *testing.B) {
	originalData := []byte("Benchmarking the encryption of a file. This data will be large enough to test performance.")
	tmpFilePath, err := createTempFileWithData(originalData)
	if err != nil {
		b.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFilePath)

	derivedKey := deriveKey(encryptionKey, salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = encryptFileGCM(tmpFilePath, derivedKey, salt, 0)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
		os.Remove(tmpFilePath + ".cryptsec")
		os.Rename(tmpFilePath, tmpFilePath+".temp")
		os.Rename(tmpFilePath+".temp", tmpFilePath)

	}
	b.StopTimer()
}

func BenchmarkDecryption(b *testing.B) {
	originalData := []byte("Benchmarking the decryption of a file. This data will be large enough to test performance.")
	tmpFilePath, err := createTempFileWithData(originalData)
	if err != nil {
		b.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFilePath)

	derivedKey := deriveKey(encryptionKey, salt)
	err = encryptFileGCM(tmpFilePath, derivedKey, salt, 0)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = decryptFileGCM(tmpFilePath+".cryptsec", encryptionKey, 0, false)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
		os.Remove(tmpFilePath)
		os.Rename(tmpFilePath+".cryptsec", tmpFilePath)

	}
	b.StopTimer()
}
