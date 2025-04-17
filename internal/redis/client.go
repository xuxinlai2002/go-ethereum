package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
	redisCtx    = context.Background()
)

// InitRedisClient initializes the Redis client with the given configuration
func InitRedisClient(addr string, password string, db int) error {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test the connection
	_, err := redisClient.Ping(redisCtx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return nil
}

// GetRedisClient returns the Redis client instance
func GetRedisClient() *redis.Client {
	return redisClient
}

// KeyExists checks if a key exists in Redis
func KeyExists(key string) (bool, error) {
	if redisClient == nil {
		return false, fmt.Errorf("Redis client not initialized")
	}

	exists, err := redisClient.Exists(redisCtx, key).Result()
	if err != nil {
		return false, err
	}

	return exists > 0, nil
}

// Set sets a key-value pair in Redis
func Set(key string, value interface{}, expiration time.Duration) error {
	if redisClient == nil {
		return fmt.Errorf("Redis client not initialized")
	}

	return redisClient.Set(redisCtx, key, value, expiration).Err()
}
