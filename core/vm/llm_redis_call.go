package vm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/sha3"
)

// LLMRedisCall handles Redis caching operations for LLM responses
type LLMRedisCall struct {
	client *redis.ClusterClient
}

var (
	// Singleton instance for Redis client
	llmRedisInstance *LLMRedisCall
	redisOnce        sync.Once
	nodeIDOnce       sync.Once

	// Node ID for the current node
	nodeID string
)

// SetNodeID sets the node ID for Redis key prefixing
func SetNodeID(id string) {
	nodeID = id
}

// GetNodeID returns the current node ID
func GetNodeID() string {
	nodeIDOnce.Do(func() {
		if nodeID == "" {
			// Get hostname
			hostname, err := os.Hostname()
			if err != nil {
				hostname = "unknown-host"
			}

			// Get process ID
			pid := os.Getpid()

			// Combine hostname and pid as the node ID
			nodeID = fmt.Sprintf("%s-%d", hostname, pid)

			log.Info("Generated node ID for Redis keys",
				"nodeID", nodeID,
				"hostname", hostname,
				"pid", pid)
		}
	})
	return nodeID
}

// GetLLMRedisCallInstance returns the singleton instance of LLMRedisCall
func GetLLMRedisCallInstance() *LLMRedisCall {
	redisOnce.Do(func() {
		// Get working directory from environment variable
		workDir := os.Getenv("workdir")
		if workDir == "" {
			log.Error("workdir environment variable is not set")
			return
		}

		// Build the complete path for the config file
		configFile := filepath.Join(workDir, "config", "llmSetting.json")
		data, err := os.ReadFile(configFile)
		if err != nil {
			log.Error("Failed to read config file", "error", err)
			return
		}

		var config struct {
			RedisIP       string `json:"redis_ip"`
			RedisPort     int    `json:"redis_port"`
			RedisPassword string `json:"redis_password"`
		}

		if err := json.Unmarshal(data, &config); err != nil {
			log.Error("Failed to parse config file", "error", err)
			return
		}

		// Build Redis cluster address
		redisAddr := fmt.Sprintf("%s:%d", config.RedisIP, config.RedisPort)
		log.Info("Connecting to Redis cluster", "address", redisAddr)

		// Create Redis cluster client with configuration
		client := redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:    []string{redisAddr},
			Password: config.RedisPassword,
		})

		// Test the connection
		ctx := context.Background()
		if err := client.Ping(ctx).Err(); err != nil {
			log.Error("Failed to connect to Redis cluster", "error", err)
			return
		}

		llmRedisInstance = &LLMRedisCall{
			client: client,
		}
		log.Info("Successfully connected to Redis cluster")
	})
	return llmRedisInstance
}

// generateRedisKey creates a SHA3 hash of inputText and modelID as the Redis key
func generateRedisKey(inputText, modelID string) string {
	// Concatenate inputText and modelID
	combined := inputText + modelID
	// Calculate SHA3 hash using sha3.Sum256
	hash := sha3.Sum256([]byte(combined))
	// Convert the [32]byte to hex string
	return hex.EncodeToString(hash[:])
}

// GetFromRedis retrieves cached LLM response using inputText as key
func (llm *LLMRedisCall) GetFromRedis(inputText, modelID string) (string, error) {
	log.Info("Attempting to get value from Redis", "inputText", inputText, "modelID", modelID)
	if llm.client == nil {
		return "", fmt.Errorf("Redis client not initialized")
	}

	key := generateRedisKey(inputText, modelID)
	ctx := context.Background()

	// Use inputText as key to get result from Redis
	result, err := llm.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("key not found in Redis")
	} else if err != nil {
		return "", fmt.Errorf("Redis error: %v", err)
	}

	log.Info("Successfully retrieved value from Redis", "key", key)
	return result, nil
}

// GetFromRedisWithSubscribe retrieves cached LLM response using inputText as key
// If key doesn't exist, subscribe and wait for the value
func (llm *LLMRedisCall) GetFromRedisWithSubscribe(inputText string, _ time.Duration) (string, error) {
	log.Info("Attempting to get value from Redis with subscribe", "inputText", inputText)
	if llm.client == nil {
		return "", fmt.Errorf("Redis client not initialized")
	}

	ctx := context.Background()

	// First try to get the value directly
	result, err := llm.client.Get(ctx, inputText).Result()
	if err == redis.Nil {
		log.Info("Key not found in Redis", "key", inputText)
		return "", fmt.Errorf("key not found in Redis")
	}
	if err != nil {
		return "", fmt.Errorf("Redis error: %v", err)
	}

	log.Info("Successfully retrieved value from Redis", "key", inputText)
	return result, nil
}

// SetToRedis stores LLM response in Redis with expiration time
func (llm *LLMRedisCall) SetToRedis(inputText, modelID, outputText string) error {
	log.Info("Attempting to set value in Redis", "inputText", inputText, "modelID", modelID)
	if llm.client == nil {
		return fmt.Errorf("Redis client not initialized")
	}

	key := generateRedisKey(inputText, modelID)
	ctx := context.Background()

	// Set value with expiration
	expiration := 24 * time.Hour
	err := llm.client.Set(ctx, key, outputText, expiration).Err()
	if err != nil {
		return fmt.Errorf("Failed to set value in Redis: %v", err)
	}

	log.Info("Successfully set value in Redis", "key", key)
	return nil
}

// Publish publishes a message to a Redis channel
func (llm *LLMRedisCall) Publish(channel string, message string) error {
	if llm.client == nil {
		return fmt.Errorf("Redis client not initialized")
	}
	return llm.client.Publish(context.Background(), channel, message).Err()
}

// Set sets a key-value pair in Redis with an optional expiration time
func (llm *LLMRedisCall) Set(key string, value string, expiration time.Duration) error {
	if llm.client == nil {
		return fmt.Errorf("Redis client not initialized")
	}
	return llm.client.Set(context.Background(), key, value, expiration).Err()
}

// KeyExists checks if a key exists in Redis
func (llm *LLMRedisCall) KeyExists(key string) (bool, error) {
	if llm.client == nil {
		return false, fmt.Errorf("Redis client not initialized")
	}
	result, err := llm.client.Exists(context.Background(), key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// Close terminates the Redis connection
func (llm *LLMRedisCall) Close() error {
	log.Info("Closing Redis connection")
	if llm.client != nil {
		return llm.client.Close()
	}
	return nil
}

// RPush adds a value to the end of a list in Redis
func (r *LLMRedisCall) RPush(key string, value string) error {
	if r.client == nil {
		return fmt.Errorf("Redis client is not initialized")
	}

	ctx := context.Background()
	return r.client.RPush(ctx, key, value).Err()
}
