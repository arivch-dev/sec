package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	saltSize      = 16
	nonceSize     = 12
)

type CryptoEngine struct {
	mu            sync.RWMutex
	activeKEK     []byte
	activeVersion int
	oldKEKs       map[int][]byte
	password      string
	keysDir       string
}

func NewCryptoEngine(password string, keysDir string) (*CryptoEngine, error) {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	engine := &CryptoEngine{
		oldKEKs:  make(map[int][]byte),
		password: password,
		keysDir:  keysDir,
	}

	legacyFile := filepath.Join(filepath.Dir(keysDir), "master.key.enc")
	v1File := filepath.Join(keysDir, "kek.v1.enc")
	if _, err := os.Stat(legacyFile); err == nil {
		if _, err := os.Stat(v1File); os.IsNotExist(err) {
			data, err := os.ReadFile(legacyFile)
			if err == nil {
				_ = os.WriteFile(v1File, data, 0600)
			}
		}
	}

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys directory: %w", err)
	}

	versions := make([]int, 0)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "kek.v") && strings.HasSuffix(name, ".enc") {
			vStr := strings.TrimSuffix(strings.TrimPrefix(name, "kek.v"), ".enc")
			if v, err := strconv.Atoi(vStr); err == nil {
				versions = append(versions, v)
			}
		}
	}

	sort.Ints(versions)

	if len(versions) == 0 {

		key, err := engine.generateAndSaveKey(1)
		if err != nil {
			return nil, fmt.Errorf("failed to generate initial KEK v1: %w", err)
		}
		engine.activeVersion = 1
		engine.activeKEK = key
		engine.oldKEKs[1] = key
	} else {

		for _, v := range versions {
			keyPath := filepath.Join(keysDir, fmt.Sprintf("kek.v%d.enc", v))
			key, err := engine.loadAndDecryptKey(keyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load KEK version %d: %w", v, err)
			}
			engine.oldKEKs[v] = key
		}

		maxV := versions[len(versions)-1]
		engine.activeVersion = maxV
		engine.activeKEK = engine.oldKEKs[maxV]
	}

	return engine, nil
}

func (e *CryptoEngine) GetActiveKEKVersion() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeVersion
}

func (e *CryptoEngine) RotateMasterKey() (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	newVersion := e.activeVersion + 1
	newKEK, err := e.generateAndSaveKey(newVersion)
	if err != nil {
		return 0, fmt.Errorf("failed to persist new KEK v%d: %w", newVersion, err)
	}

	e.oldKEKs[newVersion] = newKEK
	e.activeKEK = newKEK
	e.activeVersion = newVersion

	return newVersion, nil
}

func (e *CryptoEngine) GenerateDataKey() (plaintextDEK []byte, ciphertextDEK []byte, err error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	plaintextDEK = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, plaintextDEK); err != nil {
		return nil, nil, err
	}

	ciphertextDEK, err = e.encryptWithKey(plaintextDEK, e.activeKEK)
	if err != nil {
		return nil, nil, err
	}

	return plaintextDEK, ciphertextDEK, nil
}

func (e *CryptoEngine) DecryptDataKey(ciphertextDEK []byte, kekVersion int) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	kek, exists := e.oldKEKs[kekVersion]
	if !exists {
		if kekVersion == e.activeVersion {
			kek = e.activeKEK
		} else {
			return nil, fmt.Errorf("KEK version %d not found in storage", kekVersion)
		}
	}

	return e.decryptWithKey(ciphertextDEK, kek)
}

func (e *CryptoEngine) generateAndSaveKey(version int) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	encryptedKey, salt, nonce, err := e.encryptKeyWithPassword(key, e.password)
	if err != nil {
		return nil, err
	}

	keyFilePath := filepath.Join(e.keysDir, fmt.Sprintf("kek.v%d.enc", version))
	file, err := os.OpenFile(keyFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := file.Write(salt); err != nil {
		return nil, err
	}
	if _, err := file.Write(nonce); err != nil {
		return nil, err
	}
	if _, err := file.Write(encryptedKey); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *CryptoEngine) loadAndDecryptKey(keyFilePath string) ([]byte, error) {
	data, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	if len(data) < saltSize+nonceSize+1 {
		return nil, errors.New("key file is corrupted or too small")
	}

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+nonceSize]
	encryptedKey := data[saltSize+nonceSize:]

	key, err := e.decryptKeyWithPassword(encryptedKey, e.password, salt, nonce)
	if err != nil {
		return nil, errors.New("failed to decrypt master key: check password")
	}

	return key, nil
}

func (e *CryptoEngine) encryptKeyWithPassword(key []byte, password string) ([]byte, []byte, []byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, err
	}

	derivedKey := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}

	encrypted := aesGCM.Seal(nil, nonce, key, nil)

	return encrypted, salt, nonce, nil
}

func (e *CryptoEngine) decryptKeyWithPassword(encryptedKey []byte, password string, salt, nonce []byte) ([]byte, error) {
	derivedKey := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	key, err := aesGCM.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (e *CryptoEngine) encryptWithKey(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *CryptoEngine) decryptWithKey(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
