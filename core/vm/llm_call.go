package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// LLMResponse represents the response from the LLM service
type LLMResponse struct {
	Text string `json:"text"`
}

// callLLM calls the LLM service with the given input text and returns the response
func callLLM(inputText, modelID string, maxOutputLength uint64) string {
	log.Info("xxl llm_call.go callLLM 00", "inputText", inputText, "modelID", modelID, "maxOutputLength", maxOutputLength)

	// Try to get from Redis first
	redisClient := GetLLMRedisCallInstance()
	cachedResult, err := redisClient.GetFromRedis(inputText, modelID)
	if err == nil {
		log.Info("####xxl 0000 Cache hit", "inputText", inputText, "result", cachedResult)

		// Store the cached result in preExecV2_%s using the hash from GetSharedHash()
		// Format the data to match the format from direct API calls:
		// 1. Use RPush to store as an array in Redis
		// 2. Append [DONE] as the last element
		hash := GetSharedHash()
		// Remove 0x prefix from hash
		hashHex := hash.Hex()
		if bytes.HasPrefix([]byte(hashHex), []byte("0x")) {
			hashHex = hashHex[2:]
		}
		preExecKey := fmt.Sprintf("preExecV2_%s", hashHex)

		// Split the result by newlines to create an array
		lines := bytes.Split([]byte(cachedResult), []byte("\n"))

		// Use RPush to store each line as an element in the Redis list
		for _, line := range lines {
			if err := redisClient.RPush(preExecKey, string(line)); err != nil {
				log.Warn("Failed to RPush line to preExecV2", "error", err, "line", string(line))
			}
		}

		// Add [DONE] as the last element
		if err := redisClient.RPush(preExecKey, "[DONE]"); err != nil {
			log.Warn("Failed to RPush [DONE] to preExecV2", "error", err)
		} else {
			log.Info("Successfully stored array in preExecV2", "key", preExecKey)
		}

		return cachedResult
	}
	log.Info("xxl 0001 llm_call.go callLLM 00 : Cache miss, calling LLM service", "inputText", inputText)

	// If key not found in Redis, call LLM service
	result := realCallLLM(inputText, modelID, maxOutputLength)

	log.Info("xxl 0002 llm_call.go callLLM 00 :", "result", result)
	// Store result in Redis
	if err := redisClient.SetToRedis(inputText, modelID, result); err != nil {
		log.Error("Failed to cache result", "error", err)
	}

	return result
}

// realCallLLM makes the actual HTTP call to the LLM service
func realCallLLM(inputText, modelID string, maxOutputLength uint64) string {
	// Get LLM service URL from environment
	llmServiceURL := os.Getenv("LLM_SERVICE_URL")
	if llmServiceURL == "" {
		llmServiceURL = "http://localhost:8080/infer" // Default URL
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"input_text":        inputText,
		"model_id":          modelID,
		"max_output_length": maxOutputLength,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		log.Error("Failed to marshal request body", "error", err)
		return ""
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Make HTTP request
	resp, err := client.Post(llmServiceURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Error("Failed to call LLM service", "error", err)
		return ""
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read response body", "error", err)
		return ""
	}

	// Parse response
	var llmResp LLMResponse
	if err := json.Unmarshal(body, &llmResp); err != nil {
		log.Error("Failed to parse response", "error", err)
		return ""
	}

	return llmResp.Text
}
