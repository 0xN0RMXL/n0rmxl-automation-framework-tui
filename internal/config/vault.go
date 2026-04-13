package config

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

var (
	vaultMagic   = []byte{'R', 'P', 'V', 'T'}
	vaultVersion = byte(1)
)

type Vault struct {
	path     string
	unlocked bool
	data     map[string]string
	key      []byte
	salt     []byte
}

func NewVault(path string) *Vault {
	return &Vault{path: expandPath(path), data: map[string]string{}}
}

func (v *Vault) Create(password string) error {
	if len(password) == 0 {
		return errors.New("vault password cannot be empty")
	}
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}
	key, salt, err := deriveKey(password, nil)
	if err != nil {
		return err
	}
	v.unlocked = true
	v.data = make(map[string]string)
	v.key = make([]byte, len(key))
	v.salt = make([]byte, len(salt))
	copy(v.key, key)
	copy(v.salt, salt)
	if err := writeEncrypted(v.path, v.key, v.salt, v.data); err != nil {
		v.Lock()
		return err
	}
	return nil
}

func (v *Vault) Unlock(password string) error {
	if strings.TrimSpace(password) == "" {
		return errors.New("vault password cannot be empty")
	}
	data, key, salt, err := decryptVault(v.path, password)
	if err != nil {
		return err
	}
	v.data = data
	v.key = key
	v.salt = salt
	v.unlocked = true
	return nil
}

func (v *Vault) Lock() {
	for i := range v.key {
		v.key[i] = 0
	}
	v.key = nil
	for i := range v.salt {
		v.salt[i] = 0
	}
	v.salt = nil
	for key := range v.data {
		delete(v.data, key)
	}
	v.data = map[string]string{}
	v.unlocked = false
}

func (v *Vault) IsLocked() bool {
	return !v.unlocked
}

func (v *Vault) Get(key string) (string, bool) {
	if !v.unlocked {
		return "", false
	}
	val, ok := v.data[key]
	return val, ok
}

func (v *Vault) Set(key string, value string) error {
	if !v.unlocked {
		return errors.New("vault is locked")
	}
	if strings.TrimSpace(key) == "" {
		return errors.New("vault key cannot be empty")
	}
	v.data[key] = value
	if err := writeEncrypted(v.path, v.key, v.salt, v.data); err != nil {
		return err
	}
	return nil
}

func (v *Vault) Delete(key string) error {
	if !v.unlocked {
		return errors.New("vault is locked")
	}
	delete(v.data, key)
	if err := writeEncrypted(v.path, v.key, v.salt, v.data); err != nil {
		return err
	}
	return nil
}

func (v *Vault) List() []string {
	if !v.unlocked {
		return nil
	}
	keys := make([]string, 0, len(v.data))
	for key := range v.data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (v *Vault) InjectToEnv() error {
	if !v.unlocked {
		return errors.New("vault is locked")
	}
	for key, value := range v.data {
		envKey := mapVaultKeyToEnv(key)
		if envKey == "" {
			continue
		}
		if err := os.Setenv(envKey, value); err != nil {
			return fmt.Errorf("failed to export %s: %w", envKey, err)
		}
	}
	return nil
}

func (v *Vault) InjectToConfig(c *Config) error {
	if c == nil {
		return errors.New("config is nil")
	}
	if !v.unlocked {
		return errors.New("vault is locked")
	}
	if value, ok := v.data["burp_api_key"]; ok {
		c.Burp.APIKey = value
	}
	if value, ok := v.data["telegram_bot_token"]; ok {
		c.Notify.Telegram.BotToken = value
	}
	if value, ok := v.data["telegram_chat_id"]; ok {
		c.Notify.Telegram.ChatID = value
	}
	if value, ok := v.data["slack_webhook"]; ok {
		c.Notify.Slack.WebhookURL = value
	}
	if value, ok := v.data["discord_webhook"]; ok {
		c.Notify.Discord.WebhookURL = value
	}
	return nil
}

func PromptPassword(prompt string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	if strings.TrimSpace(prompt) == "" {
		prompt = "Vault passphrase"
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		if errors.Is(err, term.ErrPasteIndicator) {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return "", readErr
			}
			return strings.TrimSpace(line), nil
		}
		return "", err
	}
	return strings.TrimSpace(string(passwordBytes)), nil
}

func writeEncrypted(path string, key []byte, salt []byte, data map[string]string) error {
	path = expandPath(path)
	if len(key) != 32 {
		return errors.New("invalid vault encryption key")
	}
	if len(salt) != 16 {
		return errors.New("invalid vault salt")
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to encode vault payload: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to initialize AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to initialize GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, payload, nil)

	buf := new(bytes.Buffer)
	buf.Write(vaultMagic)
	buf.WriteByte(vaultVersion)
	buf.Write(salt)
	if err := binary.Write(buf, binary.BigEndian, uint32(len(ciphertext))); err != nil {
		return fmt.Errorf("failed to encode ciphertext length: %w", err)
	}
	buf.Write(ciphertext)

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write vault file %s: %w", path, err)
	}
	return nil
}

func decryptVault(path string, password string) (map[string]string, []byte, []byte, error) {
	path = expandPath(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, fmt.Errorf("vault file does not exist at %s", path)
		}
		return nil, nil, nil, err
	}
	if len(raw) < 25 {
		return nil, nil, nil, errors.New("vault file is malformed")
	}
	if !bytes.Equal(raw[:4], vaultMagic) {
		return nil, nil, nil, errors.New("vault magic header mismatch")
	}

	var (
		saltStart   int
		cipherStart int
	)
	switch {
	case raw[4] == vaultVersion:
		saltStart = 5
		cipherStart = 21
	case len(raw) >= 26 && raw[4] == 0 && raw[5] == vaultVersion:
		// Backward-compatible read path for the legacy uint16 version field.
		saltStart = 6
		cipherStart = 22
	default:
		return nil, nil, nil, fmt.Errorf("unsupported vault version header")
	}
	if len(raw) < cipherStart+4 {
		return nil, nil, nil, errors.New("vault file is malformed")
	}
	salt := raw[saltStart : saltStart+16]
	cipherLen := binary.BigEndian.Uint32(raw[cipherStart : cipherStart+4])
	if len(raw) < cipherStart+4+int(cipherLen) {
		return nil, nil, nil, errors.New("vault ciphertext length mismatch")
	}
	ciphertext := raw[cipherStart+4 : cipherStart+4+int(cipherLen)]

	key, _, err := deriveKey(password, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, nil, nil, errors.New("vault ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	encPayload := ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, encPayload, nil)
	if err != nil {
		return nil, nil, nil, errors.New("failed to decrypt vault: invalid passphrase or corrupted file")
	}
	data := make(map[string]string)
	if len(plain) > 0 {
		if err := json.Unmarshal(plain, &data); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode vault payload: %w", err)
		}
	}
	outSalt := make([]byte, len(salt))
	copy(outSalt, salt)
	return data, key, outSalt, nil
}

func deriveKey(password string, salt []byte) ([]byte, []byte, error) {
	if strings.TrimSpace(password) == "" {
		return nil, nil, errors.New("vault passphrase cannot be empty")
	}
	if len(salt) == 0 {
		salt = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, fmt.Errorf("failed to generate vault salt: %w", err)
		}
	}
	key := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)
	return key, salt, nil
}

func mapVaultKeyToEnv(key string) string {
	switch key {
	case "virustotal":
		return "VT_API_KEY"
	case "shodan":
		return "SHODAN_API_KEY"
	case "censys_id":
		return "CENSYS_API_ID"
	case "censys_secret":
		return "CENSYS_API_SECRET"
	case "chaos":
		return "PDCP_API_KEY"
	case "github_token":
		return "GITHUB_TOKEN"
	case "gitlab_token":
		return "GITLAB_TOKEN"
	case "securitytrails":
		return "SECURITYTRAILS_KEY"
	case "binaryedge":
		return "BINARYEDGE_API_KEY"
	case "hunter":
		return "HUNTER_API_KEY"
	case "burp_api_key":
		return "BURP_API_KEY"
	case "telegram_bot_token":
		return "TELEGRAM_BOT_TOKEN"
	case "telegram_chat_id":
		return "TELEGRAM_CHAT_ID"
	case "slack_webhook":
		return "SLACK_WEBHOOK_URL"
	case "discord_webhook":
		return "DISCORD_WEBHOOK_URL"
	default:
		return ""
	}
}

func expandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return path
}
