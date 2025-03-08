package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	Verbose        bool
}

func parseFlags() Config {
	encrypt := flag.Bool("e", false, "Encrypt files")
	decrypt := flag.Bool("d", false, "Decrypt files")
	directory := flag.String("r", "", "Directory to process")
	singleFile := flag.String("f", "", "Single file to process")
	threads := flag.Int("t", 3, "Number of threads for multithreading")
	passesPtr := flag.Int("p", -1, "Number of passes for secure overwrite (-1 for keep, 0 for normal removal)")
	cat := flag.Bool("c", false, "Display decrypted content in terminal (does not alter original file)")
	verbose := flag.Bool("v", false, "Enable verbose output")

	flag.Parse()

	if *encrypt && *decrypt {
		log.Println("Cannot use -e and -d together. Exiting.")
		os.Exit(1)
	}

	useMultithread := *threads > 1
	passes := *passesPtr

	return Config{
		Encrypt:        *encrypt,
		Decrypt:        *decrypt,
		Directory:      *directory,
		Threads:        *threads,
		SingleFile:     *singleFile,
		UseMultithread: useMultithread,
		Passes:         passes,
		Cat:            *cat,
		Verbose:        *verbose,
	}
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

func getKeyForEncryption() ([]byte, []byte, error) {
	fmt.Print("Enter encryption key: ")
	key1, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	fmt.Print("Confirm encryption key: ")
	key2, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

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

func processSingleFile(filePath string, key, salt []byte, encrypt, decrypt bool, passes int, cat, verbose bool) error {
	startTime := time.Now()
	var err error
	if encrypt {
		err = encryptFileGCM(filePath, key, salt, passes)
	} else if decrypt {
		err = decryptFileGCM(filePath, key, passes, cat)
	}
	duration := time.Since(startTime)
	if err != nil {
		return err
	}
	durationStr := formatDuration(duration)
	if verbose {
		if encrypt {
			log.Printf("File %s encrypted in %s\n", filePath, durationStr)
		} else {
			log.Printf("File %s decrypted in %s\n", filePath, durationStr)
		}
	}
	return nil
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

	const bufferSize = 128 * 1024
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

	if passes >= 0 {
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

		inputFile.Close()

		if passes >= 0 {
			if err := overwriteAndRemove(filePath, passes); err != nil {
				return fmt.Errorf("failed to remove encrypted file: %w", err)
			}
		}
	}

	return nil
}

func processSingleFileConcurrently(filePath string, key, salt []byte, encrypt, decrypt bool, passes int, cat, verbose bool, wg *sync.WaitGroup, errChan chan<- error) {
	defer wg.Done()

	startTime := time.Now()
	var err error
	if encrypt {
		err = encryptFileGCM(filePath, key, salt, passes)
	} else if decrypt {
		err = decryptFileGCM(filePath, key, passes, cat)
	}
	duration := time.Since(startTime)

	if err != nil {
		errChan <- fmt.Errorf("error processing file %s: %w", filePath, err)
		return
	}
	durationStr := formatDuration(duration)
	if verbose {
		if encrypt {
			log.Printf("File %s encrypted in %s\n", filePath, durationStr)
		} else {
			log.Printf("File %s decrypted in %s\n", filePath, durationStr)
		}
	}
}

func processDirectory(files []string, key, salt []byte, config Config, printTime bool) {
	startTime := time.Now()
	fileChan := make(chan string, config.Threads)
	errChan := make(chan error, config.Threads)
	var wg sync.WaitGroup

	startWorkers(fileChan, errChan, &wg, key, salt, config, startTime)

	sendFilesToWorkers(files, fileChan)

	waitForWorkersAndCloseErrorChan(&wg, errChan)

	processErrors(errChan)

	printExecutionTime(startTime, config.Encrypt, printTime)
}

func startWorkers(fileChan chan string, errChan chan error, wg *sync.WaitGroup, key, salt []byte, config Config, startTime time.Time) {
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileChan {
				processFile(file, key, salt, config, errChan, startTime)
			}
		}()
	}
}

func processFile(file string, key, salt []byte, config Config, errChan chan error, startTime time.Time) {
	var err error
	if config.Encrypt {
		err = encryptFileGCM(file, key, salt, config.Passes)
	} else if config.Decrypt {
		err = decryptFileGCM(file, key, config.Passes, config.Cat)
	}
	if err != nil {
		errChan <- fmt.Errorf("error processing file %s: %w", file, err)
		return
	}
	if config.Verbose {
		log.Printf("File %s processed in %s\n", file, formatDuration(time.Since(startTime)))
	}
}

func sendFilesToWorkers(files []string, fileChan chan string) {
	for _, file := range files {
		fileChan <- file
	}
	close(fileChan)
}

func waitForWorkersAndCloseErrorChan(wg *sync.WaitGroup, errChan chan error) {
	wg.Wait()
	close(errChan)
}

func processErrors(errChan chan error) {
	for err := range errChan {
		log.Println(err)
	}
}

func printExecutionTime(startTime time.Time, encrypt, printTime bool) {
	if printTime {
		duration := time.Since(startTime)
		durationStr := formatDuration(duration)
		if encrypt {
			log.Printf("Encryption Time: %s\n", durationStr)
		} else {
			log.Printf("Decryption Time: %s\n", durationStr)
		}
	}
}

func processGlobPattern(pattern string, key, salt []byte, config Config) {
	var files []string
	baseDir := filepath.Dir(pattern)
	matchPattern := filepath.Base(pattern)

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			matched, err := filepath.Match(matchPattern, filepath.Base(path))
			if err != nil {
				return err
			}
			if matched {
				files = append(files, path)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("Error walking through directory: %v\n", err)
		return
	}

	processDirectory(files, key, salt, config, !config.Verbose)
}

func isWritable(filePath string) bool {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	return fileInfo.Mode().Perm()&(1<<1) != 0
}

func makeWritable(filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	return os.Chmod(filePath, fileInfo.Mode().Perm()|0200)
}

func overwriteAndRemove(filePath string, passes int) error {
	if passes <= 0 {
		return os.Remove(filePath)
	}

	if !isWritable(filePath) {
		if err := makeWritable(filePath); err != nil {
			log.Printf("Failed to make file writable: %v\n", err)
		}
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
	if err := os.Truncate(filePath, 0); err != nil {
		return fmt.Errorf("failed to truncate file: %w", err)
	}
	return os.Remove(filePath)
}

func formatDuration(d time.Duration) string {
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	} else {
		return fmt.Sprintf("%ds", s)
	}
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

	if config.Directory != "" {
		processGlobPattern(filepath.Join(config.Directory, "*"), key, salt, config)
	} else if config.SingleFile != "" {
		path := config.SingleFile
		fileInfo, err := os.Stat(path)
		if err != nil {
			log.Printf("Skipping: %s (error: %v)\n", path, err)
		} else {
			if fileInfo.IsDir() {
				processGlobPattern(filepath.Join(path, "*"), key, salt, config)
			} else {
				var wg sync.WaitGroup
				errChan := make(chan error, 1)
				wg.Add(1)
				go processSingleFileConcurrently(path, key, salt, config.Encrypt, config.Decrypt, config.Passes, config.Cat, config.Verbose, &wg, errChan)
				wg.Wait()
				close(errChan)
				if err := <-errChan; err != nil {
					log.Printf("Error processing file: %s (error: %v)\n", path, err)
				}
			}
		}
	} else if flag.NArg() > 0 {
		for _, path := range flag.Args() {
			if strings.Contains(path, "*") {
				processGlobPattern(path, key, salt, config)
			} else {
				fileInfo, err := os.Stat(path)
				if err != nil {
					log.Printf("Skipping: %s (error: %v)\n", path, err)
					continue
				}

				if fileInfo.IsDir() {
					processGlobPattern(filepath.Join(path, "*"), key, salt, config)
				} else {
					var wg sync.WaitGroup
					errChan := make(chan error, 1)
					wg.Add(1)
					go processSingleFileConcurrently(path, key, salt, config.Encrypt, config.Decrypt, config.Passes, config.Cat, config.Verbose, &wg, errChan)
					wg.Wait()
					close(errChan)
					if err := <-errChan; err != nil {
						log.Printf("Error processing file: %s (error: %v)\n", path, err)
					}
				}
			}
		}
	} else {
		log.Println("No valid input provided. Use -h for help.")
		os.Exit(1)
	}
}
