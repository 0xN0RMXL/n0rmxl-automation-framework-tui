package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Version        string       `yaml:"version" mapstructure:"version"`
	VaultPath      string       `yaml:"vault_path" mapstructure:"vault_path"`
	WorkspaceRoot  string       `yaml:"workspace_root" mapstructure:"workspace_root"`
	Burp           BurpConfig   `yaml:"burp" mapstructure:"burp"`
	Notify         NotifyConfig `yaml:"notify" mapstructure:"notify"`
	StealthProfile string       `yaml:"stealth_profile" mapstructure:"stealth_profile"`
	ScreenshotTool string       `yaml:"screenshot_tool" mapstructure:"screenshot_tool"`
	Tools          ToolPaths    `yaml:"tools" mapstructure:"tools"`
	Wordlists      Wordlists    `yaml:"wordlists" mapstructure:"wordlists"`
}

type BurpConfig struct {
	Enabled   bool   `yaml:"enabled" mapstructure:"enabled"`
	APIURL    string `yaml:"api_url" mapstructure:"api_url"`
	APIKey    string `yaml:"-" mapstructure:"-"`
	ProxyHost string `yaml:"proxy_host" mapstructure:"proxy_host"`
	ProxyPort int    `yaml:"proxy_port" mapstructure:"proxy_port"`
}

type NotifyConfig struct {
	Telegram    TelegramConfig `yaml:"telegram" mapstructure:"telegram"`
	Slack       SlackConfig    `yaml:"slack" mapstructure:"slack"`
	Discord     DiscordConfig  `yaml:"discord" mapstructure:"discord"`
	MinSeverity string         `yaml:"min_severity" mapstructure:"min_severity"`
}

type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	BotToken string `yaml:"-" mapstructure:"-"`
	ChatID   string `yaml:"-" mapstructure:"-"`
}

type SlackConfig struct {
	Enabled    bool   `yaml:"enabled" mapstructure:"enabled"`
	WebhookURL string `yaml:"-" mapstructure:"-"`
}

type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled" mapstructure:"enabled"`
	WebhookURL string `yaml:"-" mapstructure:"-"`
}

type ToolPaths struct {
	GoBin     string `yaml:"go_bin" mapstructure:"go_bin"`
	PythonBin string `yaml:"python_bin" mapstructure:"python_bin"`
	GitClones string `yaml:"git_clones" mapstructure:"git_clones"`
}

type Wordlists struct {
	DNSLarge   string `yaml:"dns_large" mapstructure:"dns_large"`
	DNSMedium  string `yaml:"dns_medium" mapstructure:"dns_medium"`
	DNSSmall   string `yaml:"dns_small" mapstructure:"dns_small"`
	DirLarge   string `yaml:"dir_large" mapstructure:"dir_large"`
	DirMedium  string `yaml:"dir_medium" mapstructure:"dir_medium"`
	FilesLarge string `yaml:"files_large" mapstructure:"files_large"`
	Params     string `yaml:"params" mapstructure:"params"`
	LFI        string `yaml:"lfi" mapstructure:"lfi"`
	XSS        string `yaml:"xss" mapstructure:"xss"`
	Resolvers  string `yaml:"resolvers" mapstructure:"resolvers"`
	APIRoutes  string `yaml:"api_routes" mapstructure:"api_routes"`
}

func Load() (*Config, error) {
	cfgPath := defaultConfigPath()
	cfg := DefaultConfig()
	v := viper.New()
	v.SetConfigFile(cfgPath)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		var cfgErr viper.ConfigFileNotFoundError
		if !errors.As(err, &cfgErr) && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to read config file %s: %w", cfgPath, err)
		}
		cfg.EnsureDefaults()
		if err := cfg.Save(); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", cfgPath, err)
	}
	cfg.EnsureDefaults()
	if err := cfg.Save(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Save() error {
	if c == nil {
		return errors.New("config is nil")
	}
	c.EnsureDefaults()
	cfgPath := defaultConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	content, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", cfgPath, err)
	}
	return nil
}

func (c *Config) EnsureDefaults() {
	if c.Version == "" {
		c.Version = "1"
	}
	if c.VaultPath == "" {
		c.VaultPath = filepath.ToSlash(filepath.Join(defaultConfigDir(), "vault.enc"))
	}
	if c.WorkspaceRoot == "" {
		c.WorkspaceRoot = filepath.ToSlash(defaultWorkspaceRoot())
	}
	if c.Burp.APIURL == "" {
		c.Burp.APIURL = "http://127.0.0.1:1337"
	}
	if c.Burp.ProxyHost == "" {
		c.Burp.ProxyHost = "127.0.0.1"
	}
	if c.Burp.ProxyPort == 0 {
		c.Burp.ProxyPort = 8080
	}
	if c.StealthProfile == "" {
		c.StealthProfile = "normal"
	}
	if c.ScreenshotTool == "" {
		c.ScreenshotTool = "gowitness"
	}
	if c.Notify.MinSeverity == "" {
		c.Notify.MinSeverity = "high"
	}

	if c.Tools.GoBin == "" {
		home, _ := os.UserHomeDir()
		c.Tools.GoBin = filepath.ToSlash(filepath.Join(home, "go", "bin"))
	}
	if c.Tools.PythonBin == "" {
		c.Tools.PythonBin = "/usr/bin/python3"
	}
	if c.Tools.GitClones == "" {
		c.Tools.GitClones = filepath.ToSlash(filepath.Join(defaultDataDir(), "tools"))
	}

	localDNSLarge := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "dns", "best-dns-wordlist.txt"))
	localDNSMedium := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "dns", "commonspeak2-subdomains.txt"))
	localDNSSmall := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "dns", "best-dns-wordlist.txt"))
	localDirLarge := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "web", "raft-large-directories.txt"))
	localDirMedium := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "web", "raft-medium-directories.txt"))
	localFilesLarge := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "web", "raft-large-files.txt"))
	localParams := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "params", "burp-parameter-names.txt"))
	localLFI := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "fuzzing", "LFI-Jhaddix.txt"))
	localXSS := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "fuzzing", "XSS-Jhaddix.txt"))
	localResolvers := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "dns", "resolvers.txt"))
	localAPIRoutes := filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "api", "api-routes.txt"))

	c.Wordlists.DNSLarge = useLocalWordlistDefault(c.Wordlists.DNSLarge, localDNSLarge, "/usr/share/seclists/Discovery/DNS/best-dns-wordlist.txt")
	c.Wordlists.DNSMedium = useLocalWordlistDefault(c.Wordlists.DNSMedium, localDNSMedium, "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt")
	c.Wordlists.DNSSmall = useLocalWordlistDefault(c.Wordlists.DNSSmall, localDNSSmall, "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt")
	c.Wordlists.DirLarge = useLocalWordlistDefault(c.Wordlists.DirLarge, localDirLarge, "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt")
	c.Wordlists.DirMedium = useLocalWordlistDefault(c.Wordlists.DirMedium, localDirMedium, "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
	c.Wordlists.FilesLarge = useLocalWordlistDefault(c.Wordlists.FilesLarge, localFilesLarge, "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt")
	c.Wordlists.Params = useLocalWordlistDefault(c.Wordlists.Params, localParams, "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt")
	c.Wordlists.LFI = useLocalWordlistDefault(c.Wordlists.LFI, localLFI, "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt")
	c.Wordlists.XSS = useLocalWordlistDefault(c.Wordlists.XSS, localXSS, "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt")
	c.Wordlists.Resolvers = useLocalWordlistDefault(c.Wordlists.Resolvers, localResolvers, "/usr/share/seclists/Miscellaneous/dns-resolvers.txt")
	c.Wordlists.APIRoutes = useLocalWordlistDefault(c.Wordlists.APIRoutes, localAPIRoutes, filepath.ToSlash(filepath.Join(defaultDataDir(), "wordlists", "api-routes.txt")))
}

func (c *Config) Validate() []string {
	warnings := make([]string, 0, 16)
	if c == nil {
		return []string{"config is nil"}
	}
	if c.StealthProfile != "slow" && c.StealthProfile != "normal" && c.StealthProfile != "aggressive" {
		warnings = append(warnings, "stealth_profile should be one of slow|normal|aggressive")
	}
	if !strings.HasPrefix(c.Burp.APIURL, "http://") && !strings.HasPrefix(c.Burp.APIURL, "https://") {
		warnings = append(warnings, "burp.api_url should start with http:// or https://")
	}
	if c.Burp.ProxyPort <= 0 || c.Burp.ProxyPort > 65535 {
		warnings = append(warnings, "burp.proxy_port should be between 1 and 65535")
	}
	if c.Notify.MinSeverity != "critical" && c.Notify.MinSeverity != "high" && c.Notify.MinSeverity != "medium" && c.Notify.MinSeverity != "low" && c.Notify.MinSeverity != "info" {
		warnings = append(warnings, "notify.min_severity should be one of critical|high|medium|low|info")
	}
	if strings.TrimSpace(c.WorkspaceRoot) == "" {
		warnings = append(warnings, "workspace_root should not be empty")
	}
	if strings.TrimSpace(c.VaultPath) == "" {
		warnings = append(warnings, "vault_path should not be empty")
	}
	return warnings
}

func DefaultConfig() *Config {
	cfg := &Config{}
	cfg.EnsureDefaults()
	return cfg
}

func useLocalWordlistDefault(current string, local string, legacy ...string) string {
	current = strings.TrimSpace(current)
	local = strings.TrimSpace(local)
	if current == "" {
		return local
	}
	if local == "" {
		return current
	}
	currentNorm := normalizePath(current)
	for _, candidate := range legacy {
		if currentNorm == normalizePath(candidate) {
			return local
		}
	}
	return current
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
}

func defaultConfigPath() string {
	if override := strings.TrimSpace(os.Getenv("N0RMXL_CONFIG")); override != "" {
		return override
	}
	return filepath.Join(defaultConfigDir(), "config.yaml")
}

func defaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".config", "n0rmxl")
	}
	return filepath.Join(home, ".config", "n0rmxl")
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".local", "share", "n0rmxl")
	}
	return filepath.Join(home, ".local", "share", "n0rmxl")
}

func defaultWorkspaceRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "bounty")
	}
	return filepath.Join(home, "bounty")
}
