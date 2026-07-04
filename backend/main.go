package main

import (
	log "boarding-pass/logging"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"strconv"
)

type Config struct {
	ServerConfig     ServerConfig     `json:"server_config"`
	CredentialConfig CredentialConfig `json:"credential_config"`
	StorageConfig    StorageConfig    `json:"storage_config"`
}

type StorageConfig struct {
	Type                string              `json:"type"`
	RedisConfig         RedisConfig         `json:"redis_config"`
	RedisSentinelConfig RedisSentinelConfig `json:"redis_sentinel_config"`
}

type RedisConfig struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Password  string `json:"password"`
	Namespace string `json:"namespace"`
}

type RedisSentinelConfig struct {
	SentinelHost      string `json:"sentinel_host"`
	SentinelPort      int    `json:"sentinel_port"`
	MasterName        string `json:"master_name"`
	Password          string `json:"password"`
	SentinelNamespace string `json:"sentinel_namespace"`
	SentinelUsername  string `json:"sentinel_username"`
}

type CredentialConfig struct {
	PrivateKeyPath string `json:"private_key_path"`
	IrmaServerURL  string `json:"irma_server_url"`
	RequestorId    string `json:"requestor_id"`
	Scheme         string `json:"scheme"`
	NextSessionURL string `json:"next_session_url"`
}

func main() {

	configPath := flag.String("config", "", "Path for the config.json to use")
	debug := flag.Bool("debug", false, "Enable debug logging (emits raw error values; keep off in production)")
	flag.Parse()

	log.SetDebug(*debug)

	if *configPath == "" {
		log.Error.Fatal("please provide a config path using the --config flag")
	}

	log.Info.Printf("using config: %v", *configPath)

	config, err := readConfigFile(*configPath)
	if err != nil {
		log.Error.Fatalf("failed to read config file: %v", err)
	}
	tokenStorage := NewTokenStorage(&config.StorageConfig)

	serverState := &ServerState{
		irmaServerURL:    config.CredentialConfig.IrmaServerURL,
		tokenStorage:     tokenStorage,
		credentialConfig: config.CredentialConfig,
		serverConfig:     config.ServerConfig,
	}

	server := NewServer(serverState, &config.ServerConfig)

	log.Info.Println("starting server on " + config.ServerConfig.Host + ":" + strconv.Itoa(config.ServerConfig.Port))
	err = server.server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Error.Fatalf("server failed: %v", err)
	}

}

func readConfigFile(path string) (Config, error) {
	configBytes, err := os.ReadFile(path)

	if err != nil {
		return Config{}, err
	}

	var config Config
	err = json.Unmarshal(configBytes, &config)

	if err != nil {
		return Config{}, err
	}

	return config, nil
}
