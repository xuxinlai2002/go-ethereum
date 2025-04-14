package vm

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
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
		// Get Redis configuration from environment
		redisAddr := os.Getenv("REDIS_ADDR")
		if redisAddr == "" {
			redisAddr = "localhost:6379" // Default Redis address
		}

		// Create Redis client
		client := redis.NewClusterClient(&redis.ClusterOptions{
			Addrs: []string{redisAddr},
		})

		// Test connection
		ctx := context.Background()
		if err := client.Ping(ctx).Err(); err != nil {
			log.Error("Failed to connect to Redis", "error", err)
			return
		}

		llmRedisInstance = &LLMRedisCall{
			client: client,
		}

		log.Info("Successfully initialized Redis client", "address", redisAddr)
	})

	return llmRedisInstance
}

// GetFromRedis retrieves a cached LLM response from Redis
func (r *LLMRedisCall) GetFromRedis(inputText, modelID string) (string, error) {
	if r.client == nil {
		return "", fmt.Errorf("Redis client not initialized")
	}

	// Generate cache key
	key := r.generateCacheKey(inputText, modelID)

	// Try to get from Redis
	ctx := context.Background()
	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // Cache miss
	} else if err != nil {
		return "", err
	}

	return val, nil
}

// SetToRedis stores an LLM response in Redis cache
func (r *LLMRedisCall) SetToRedis(inputText, modelID, response string) error {
	if r.client == nil {
		return fmt.Errorf("Redis client not initialized")
	}

	// Generate cache key
	key := r.generateCacheKey(inputText, modelID)

	// Store in Redis with expiration
	ctx := context.Background()
	err := r.client.Set(ctx, key, response, 24*time.Hour).Err()
	if err != nil {
		return err
	}

	return nil
}

// RPush adds a value to the end of a Redis list
func (r *LLMRedisCall) RPush(key string, value string) error {
	if r.client == nil {
		return fmt.Errorf("Redis client not initialized")
	}

	ctx := context.Background()
	err := r.client.RPush(ctx, key, value).Err()
	if err != nil {
		return err
	}

	return nil
}

// generateCacheKey creates a unique Redis key for caching
func (r *LLMRedisCall) generateCacheKey(inputText, modelID string) string {
	// Create a hash of the input text and model ID
	hasher := sha3.New256()
	hasher.Write([]byte(inputText))
	hasher.Write([]byte(modelID))
	hash := hasher.Sum(nil)

	// Convert hash to hex string
	hashHex := hex.EncodeToString(hash)

	// Combine with node ID and prefix
	return fmt.Sprintf("llm:%s:%s", GetNodeID(), hashHex)
}

// GetSharedHash returns a shared hash for Redis notifications
func GetSharedHash() common.Hash {
	// This is a placeholder implementation
	// In a real implementation, this would generate a unique hash based on the current context
	return common.Hash{}
}
