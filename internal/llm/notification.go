package llm

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/shared"
	"github.com/ethereum/go-ethereum/log"
)

var (
	sharedSignedTx string
)

// SetSharedSignedTx sets the shared signed transaction
func SetSharedSignedTx(tx string) {
	sharedSignedTx = tx
}

// GetSharedSignedTx returns the shared signed transaction
func GetSharedSignedTx() string {
	return sharedSignedTx
}

// NotifyLLMContract handles the LLM contract notification logic
func NotifyLLMContract(txHash common.Hash) {
	log.Info("---- LLM contract called, preparing Redis notification")

	// Get Redis client instance
	redisClient := vm.GetLLMRedisCallInstance()
	if redisClient == nil {
		log.Warn("Redis client not available for LLM notification")
		return
	}

	// Get the shared hash for Redis notification
	hash := shared.GetSharedHash()
	fmt.Println("@@@@@@@@ xxl 0000 hash", hash)
	if hash == (common.Hash{}) {
		log.Warn("Shared hash is nil, skipping Redis notification")
		return
	}

	// Construct Redis notification key using the signed transaction hash
	fmt.Println("@@@@@@@@ xxl 0001 hash", hash)
	redisKey := fmt.Sprintf("signed_tx_%x", hash)

	// First check if the key already exists
	exists, checkErr := redisClient.KeyExists(redisKey)
	if checkErr != nil {
		log.Warn("Failed to check if Redis key exists, proceeding with set operation",
			"key", redisKey,
			"error", checkErr)
		exists = false // Assume key doesn't exist if check fails
	}

	fmt.Println("@@@@@@@@ xxl 0002 exists", exists)
	// Only set the key if it doesn't already exist
	{
		// Get the signed transaction data
		signedTx := GetSharedSignedTx()
		fmt.Println("@@@@@@@@ xxl 0003 signedTx", signedTx)
		// 确保 signedTx 有 0x 前缀
		if !strings.HasPrefix(signedTx, "0x") {
			signedTx = "0x" + signedTx
		}
		// Set key in Redis (with error tolerance)
		if err := redisClient.Set(redisKey, signedTx, 0); err != nil {
			// Just log the error but continue execution
			log.Error("Redis operation failed, but transaction processing continues",
				"txHash", txHash.Hex(),
				"error", err,
				"suggestion", "Please check Redis server configuration or disk space")
		} else {
			log.Info("Successfully set transaction notification in Redis", "key", redisKey)
		}
	}
}
