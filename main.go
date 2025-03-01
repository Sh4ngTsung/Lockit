package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

type Config struct {
	Encrypt        bool
	Decrypt        bool
	Directory      string
	Threads        int
	SingleFile     string
	UseMultithread bool
	Passes         int
	Cat            bool
}

func main() {
	config := parseFlags()

	var key []byte
	var salt []byte
	var err error

	if config.Encrypt {
		key, salt, err = getKeyForEncryption()
		if err != nil {
			log.Fatalf("Error getting encryption key: %v\n", err)
		}
		defer zeroize(key)
		defer zeroize(salt)
	} else if config.Decrypt {
		key, err = getKeyForDecryption()
		if err != nil {
			log.Fatalf("Error getting decryption key: %v\n", err)
		}
		defer zeroize(key)
	} else {
		log.Println("No valid operation specified. Use -h for help.")
		os.Exit(1)
	}

	if config.SingleFile != "" {
		if config.UseMultithread {
			var wg sync.WaitGroup
			errChan := make(chan error, 1)

			wg.Add(1)
			go processSingleFileConcurrently(config.SingleFile, key, salt, config.Encrypt, config.Decrypt, config.Passes, config.Cat, &wg, errChan)

			go func() {
				wg.Wait()
				close(errChan)
			}()

			for err := range errChan {
				log.Printf("Error processing single file: %v\n", err)
			}
		} else {
			if err := processSingleFile(config.SingleFile, key, salt, config.Encrypt, config.Decrypt, config.Passes, config.Cat); err != nil {
				log.Printf("Error processing single file: %v\n", err)
			}
		}
	} else if config.Directory != "" {
		processDirectory(config.Directory, key, salt, config.Encrypt, config.Decrypt, config.UseMultithread, config.Threads, config.Passes, config.Cat)
	} else {
		log.Println("No valid input provided. Use -h for help.")
		os.Exit(1)
	}
}

func parseFlags() Config {
	encrypt := flag.Bool("e", false, "Encrypt files")
	decrypt := flag.Bool("d", false, "Decrypt files")
	directory := flag.String("r", "", "Directory to process")
	singleFile := flag.String("f", "", "Single file to process")
	threads := flag.Int("t", 3, "Number of threads for multithreading")
	passes := flag.Int("p", 0, "Number of passes for secure overwrite (0 for normal removal)")
	cat := flag.Bool("c", false, "Display decrypted content in terminal (does not alter original file)")

	flag.Parse()

	if *encrypt && *decrypt {
		log.Println("Cannot use -e and -d together. Exiting.")
		os.Exit(1)
	}

	useMultithread := *threads > 1

	return Config{
		Encrypt:        *encrypt,
		Decrypt:        *decrypt,
		Directory:      *directory,
		Threads:        *threads,
		SingleFile:     *singleFile,
		UseMultithread: useMultithread,
		Passes:         *passes,
		Cat:            *cat,
	}
}

func getKeyForEncryption() ([]byte, []byte, error) {
	fmt.Print("Enter encryption key: ")
	key1, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	fmt.Print("Confirm encryption key: ")
	key2, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	// Sanitize the passwords
	key1 = []byte(strings.TrimSpace(string(key1)))
	key2 = []byte(strings.TrimSpace(string(key2)))

	if !bytes.Equal(key1, key2) {
		return nil, nil, fmt.Errorf("keys do not match")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	derivedKey := deriveKey(key1, salt)

	defer zeroize(key1)
	defer zeroize(key2)

	return derivedKey, salt, nil
}

func getKeyForDecryption() ([]byte, error) {
	fmt.Print("Enter decryption key: ")
	key, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	key = []byte(strings.TrimSpace(string(key)))

	return key, nil
}

func deriveKey(inputKey, salt []byte) []byte {
	iterations := uint32(32)
	memory := uint32(64 * 1024)
	parallelism := uint8(4)

	return argon2.Key(inputKey, salt, iterations, memory, parallelism, 32)
}

func processSingleFile(filePath string, key, salt []byte, encrypt, decrypt bool, passes int, cat bool) error {
	if encrypt {
		return encryptFileGCM(filePath, key, salt, passes)
	} else if decrypt {
		return decryptFileGCM(filePath, key, passes, cat)
	}
	return errors.New("invalid operation: must specify -e or -d")
}

func encryptFileGCM(filePath string, key, salt []byte, passes int) error {
	if strings.HasSuffix(filePath, ".cryptsec") {
		log.Printf("Ignoring already encrypted file: %s\n", filePath)
		return nil
	}

	inputFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for encryption: %w", err)
	}
	defer inputFile.Close()

	outputPath := filePath + ".cryptsec"
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %w", err)
	}
	defer outputFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	if _, err := outputFile.Write(salt); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}
	if _, err := outputFile.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	const bufferSize = 128 * 1024 // 128 KB
	buffer := make([]byte, bufferSize)

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read plaintext: %w", err)
		}
		if n == 0 {
			break
		}

		ciphertext := gcm.Seal(nil, nonce, buffer[:n], nil)
		if _, err := outputFile.Write(ciphertext); err != nil {
			return fmt.Errorf("failed to write ciphertext: %w", err)
		}
	}

	inputFile.Close()

	if passes > 0 {
		if err := overwriteAndRemove(filePath, passes); err != nil {
			return fmt.Errorf("failed to overwrite and remove original file: %w", err)
		}
	}

	return nil
}

func decryptFileGCM(filePath string, key []byte, passes int, cat bool) error {
	if !strings.HasSuffix(filePath, ".cryptsec") {
		return fmt.Errorf("file %s is not encrypted", filePath)
	}

	inputFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer inputFile.Close()

	salt := make([]byte, 16)
	nonce := make([]byte, 12)

	if _, err := io.ReadFull(inputFile, salt); err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
	}
	if _, err := io.ReadFull(inputFile, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	derivedKey := deriveKey(key, salt)
	defer zeroize(derivedKey)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	const baseBufferSize = 128 * 1024
	bufferSize := baseBufferSize + gcm.Overhead()
	buffer := make([]byte, bufferSize)

	if cat {
		for {
			n, err := inputFile.Read(buffer)
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to read ciphertext: %w", err)
			}
			if n == 0 {
				break
			}

			plaintext, err := gcm.Open(nil, nonce, buffer[:n], nil)
			if err != nil {
				return fmt.Errorf("failed to decrypt ciphertext: %w", err)
			}

			if _, err := os.Stdout.Write(plaintext); err != nil {
				return fmt.Errorf("failed to write to terminal: %w", err)
			}
		}
		fmt.Println()
	} else {
		outputFilePath := strings.TrimSuffix(filePath, ".cryptsec")
		outputFile, err := os.Create(outputFilePath)
		if err != nil {
			return fmt.Errorf("failed to create decrypted file: %w", err)
		}
		defer outputFile.Close()

		for {
			n, err := inputFile.Read(buffer)
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to read ciphertext: %w", err)
			}
			if n == 0 {
				break
			}

			plaintext, err := gcm.Open(nil, nonce, buffer[:n], nil)
			if err != nil {
				return fmt.Errorf("failed to decrypt ciphertext: %w", err)
			}

			if _, err := outputFile.Write(plaintext); err != nil {
				return fmt.Errorf("failed to write decrypted data: %w", err)
			}
		}

		// Close the encrypted file AFTER full processing
		inputFile.Close()

		if passes > 0 {
			if err := overwriteAndRemove(filePath, passes); err != nil {
				return fmt.Errorf("failed to remove encrypted file: %w", err)
			}
		}
	}

	return nil
}

func processSingleFileConcurrently(filePath string, key, salt []byte, encrypt, decrypt bool, passes int, cat bool, wg *sync.WaitGroup, errChan chan<- error) {
	defer wg.Done()

	if encrypt {
		if err := encryptFileGCM(filePath, key, salt, passes); err != nil {
			errChan <- fmt.Errorf("error encrypting file %s: %w", filePath, err)
		}
	} else if decrypt {
		if err := decryptFileGCM(filePath, key, passes, cat); err != nil {
			errChan <- fmt.Errorf("error decrypting file %s: %w", filePath, err)
		}
	}
}

func processDirectory(directory string, key, salt []byte, encrypt, decrypt, useMultithread bool, threads int, passes int, cat bool) {
	var wg sync.WaitGroup
	fileChan := make(chan string, threads)
	errChan := make(chan error, threads)

	fileCount := 0
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileCount++
		}
		return nil
	})

	if err != nil {
		log.Printf("Error walking directory: %v\n", err)
		return
	}

	if threads > fileCount {
		threads = fileCount
	}

	if useMultithread {
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for file := range fileChan {
					if encrypt {
						if err := encryptFileGCM(file, key, salt, passes); err != nil {
							errChan <- fmt.Errorf("error encrypting file %s: %w", file, err)
						}
					} else if decrypt {
						if err := decryptFileGCM(file, key, passes, cat); err != nil {
							errChan <- fmt.Errorf("error decrypting file %s: %w", file, err)
						}
					}
				}
			}()
		}
	}

	go func() {
		err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				fileChan <- path
			}
			return nil
		})

		if err != nil {
			errChan <- fmt.Errorf("error walking directory: %w", err)
		}

		close(fileChan)
	}()

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		log.Println(err)
	}
}

func overwriteAndRemove(filePath string, passes int) error {
	if passes <= 0 {
		return os.Remove(filePath)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	size := fileInfo.Size()
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for overwrite: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, 128*1024)
	for p := 0; p < passes; p++ {
		var fillByte byte
		if p%3 == 0 {
			fillByte = 0x00
		} else if p%3 == 1 {
			fillByte = 0xFF
		} else {
			if _, err := rand.Read(buffer); err != nil {
				return fmt.Errorf("failed to generate random data: %w", err)
			}
		}

		for written := int64(0); written < size; written += int64(len(buffer)) {
			if p%3 != 2 {
				for i := range buffer {
					buffer[i] = fillByte
				}
			}
			if _, err := file.WriteAt(buffer, written); err != nil {
				return fmt.Errorf("failed to overwrite file: %w", err)
			}
		}
	}

	file.Close()
	return os.Remove(filePath)
}

func zeroize(data []byte) error {
	if data == nil {
		return fmt.Errorf("data cannot be nil")
	}

	for i := 0; i < 38; i++ {
		_, err := rand.Read(data)
		if err != nil {
			return fmt.Errorf("error generating random values: %w", err)
		}
	}
	return nil
}
