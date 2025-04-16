package vm

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/log"
)

// TokenGas represents the gas cost per token for LLM operations
const TokenGas = uint64(1000)

func callLLM(inputText, modelID string, maxOutputLength uint64) string {

	log.Info("xxl 0000 llm_precompile.go callLLM 00 :", "inputText", inputText, "modelID", modelID, "maxOutputLength", maxOutputLength)

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
		if strings.HasPrefix(hashHex, "0x") {
			hashHex = hashHex[2:]
		}
		preExecKey := fmt.Sprintf("preExecV2_%s", hashHex)

		// Split the result by newlines to create an array
		lines := strings.Split(cachedResult, "\n")

		// Use RPush to store each line as an element in the Redis list
		for _, line := range lines {
			if err := redisClient.RPush(preExecKey, line); err != nil {
				log.Warn("Failed to RPush line to preExecV2", "error", err, "line", line)
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
	log.Info("xxl 0001 llm_precompile.go callLLM 00 : Cache miss, calling LLM service", "inputText", inputText)

	// If key not found in Redis, call LLM service
	result := realCallLLM(inputText, modelID, maxOutputLength)

	log.Info("xxl 0002 llm_precompile.go callLLM 00 :", "result", result)
	// Store result in Redis
	if err := redisClient.SetToRedis(inputText, modelID, result); err != nil {
		log.Error("Failed to cache result", "error", err)
	}

	return result
}

// LLMPrecompile implements the LLM inference precompiled contract
type LLMPrecompile struct{}

// Ensure LLMPrecompile implements both PrecompiledContract and ActualGasCalculator
var _ PrecompiledContract = &LLMPrecompile{}
var _ interface {
	RefundGas(uint64, *tracing.Hooks, tracing.GasChangeReason)
} = &LLMPrecompile{}

// countTokens estimates the number of tokens in a text by counting words and punctuation
func countTokens(text string) uint64 {
	var count uint64

	// Split by whitespace first
	words := strings.Fields(text)
	count = uint64(len(words))

	// Count punctuation marks that are not part of words
	for _, r := range text {
		if unicode.IsPunct(r) {
			// Don't count apostrophes and hyphens within words
			if r != '\'' && r != '-' {
				count++
			}
		}
	}

	return count
}

// parseInputText extracts the input text from the input bytes
func parseInputText(input []byte) (string, error) {
	if len(input) < 68 { // 4(selector) + 32(maxOutputLength) + 32(inputLength)
		return "", fmt.Errorf("input too short")
	}

	inputTextLength := new(big.Int).SetBytes(input[36:68]).Uint64()
	if inputTextLength == 0 {
		return "", fmt.Errorf("input text length cannot be zero")
	}

	if uint64(len(input)) < 68+inputTextLength {
		return "", fmt.Errorf("input shorter than declared length")
	}

	return string(input[68 : 68+inputTextLength]), nil
}

// calculateGasCost calculates gas cost based on input and output tokens
func calculateGasCost(inputTokens, outputTokens uint64) uint64 {
	log.Info("xxl llm_precompile.go calculateGasCost 00")
	inputCost := inputTokens * TokenGas
	outputCost := outputTokens * TokenGas
	return inputCost + outputCost
}

// RequiredGas calculates the gas cost for the LLM inference operation
func (c *LLMPrecompile) RequiredGas(input []byte) uint64 {
	log.Info("xxl llm_precompile.go RequiredGas 00")
	var inputTokens uint64
	inputText, err := parseInputText(input)
	if err == nil {
		inputTokens = countTokens(inputText)
	}

	// Get max output tokens from input
	var maxOutputLength uint64
	if len(input) >= 36 {
		maxOutputLength = new(big.Int).SetBytes(input[4:36]).Uint64()
	}
	return calculateGasCost(inputTokens, maxOutputLength)
}

// Run executes the LLM inference precompiled contract
func (c *LLMPrecompile) Run(evm *EVM, caller common.Address, addr common.Address, input []byte, value *big.Int, readOnly bool, isSystem bool) ([]byte, error) {
	// log.Info("### xxl llm_precompile.go Run 00")
	fmt.Println("### xxl 0000 llm_precompile.go Run 00")
	// Check if input is empty
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input for LLM inference")
	}
	// Function selector is the first 4 bytes
	if len(input) < 4 {
		return nil, fmt.Errorf("invalid input length for LLM precompile")
	}
	funcSelector := input[:4]
	switch {
	case common.Bytes2Hex(funcSelector) == "9d9af8e3": // infer(bytes,uint256)
		return c.infer(input[4:])
	default:
		return nil, fmt.Errorf("unknown function selector: %x", funcSelector)
	}
}

// infer implements the infer(bytes,uint256) function
func (c *LLMPrecompile) infer(input []byte) ([]byte, error) {
	// log.Info("xxl llm_precompile.go infer 00")
	fmt.Println("### xxl 0001 llm_precompile.go infer 00")
	// Decode input parameters
	if len(input) < 32 {
		return nil, fmt.Errorf("insufficient input for infer")
	}

	maxOutputLength := new(big.Int).SetBytes(input[0:32]).Uint64()
	if maxOutputLength == 0 {
		return nil, fmt.Errorf("maxOutputLength cannot be zero")
	}

	// Extract the actual input text
	inputTextLength := new(big.Int).SetBytes(input[32:64]).Uint64()
	if inputTextLength == 0 {
		return nil, fmt.Errorf("input text length cannot be zero")
	}
	inputText := input[64 : 64+inputTextLength]
	inputTextStr := string(inputText)

	if inputTextStr == "" {
		return nil, fmt.Errorf("inputTextStr cannot be empty")
	}

	// Get working directory from environment variable
	workDir := os.Getenv("workdir")
	fmt.Println("### xxl 0002 workDir", workDir)
	if workDir == "" {
		fmt.Println("### xxl 0003 workdir environment variable is not set")
		return nil, fmt.Errorf("workdir environment variable is not set")
	}

	// Build the complete path for the config file
	configFile := filepath.Join(workDir, "config", "llmSetting.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config struct {
		ModelID string `json:"model_id"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	modelID := config.ModelID
	if modelID == "" {
		return nil, fmt.Errorf("model_id is empty in config file")
	}

	// 调用 llm_call.go 中的 realCallLLM 函数
	outputText := callLLM(inputTextStr, modelID, maxOutputLength)

	// Encode output as dynamic bytes
	outputBytes := []byte(outputText)

	log.Info("LLM infer return result ", "outputBytes length", len(outputBytes), "inputText", string(inputText), "outputText", outputText)

	return outputBytes, nil
}

// ActualGas calculates the actual gas used based on input and output
func (c *LLMPrecompile) ActualGas(input []byte, output []byte) uint64 {
	log.Info("xxl llm_precompile.go ActualGas 00")
	var inputTokens uint64
	inputText, err := parseInputText(input)
	if err == nil {
		inputTokens = countTokens(inputText)
	}

	// Calculate actual output tokens cost
	// Check if output is valid before accessing
	var outputText string
	if len(output) > 0 {
		outputText = string(output)
	}
	outputTokens := countTokens(outputText)
	return calculateGasCost(inputTokens, outputTokens)
}

// NewLLMPrecompile creates a new instance of LLMPrecompile
func NewLLMPrecompile() *LLMPrecompile {
	return &LLMPrecompile{}
}

// RefundGas implements the gas refund mechanism
func (c *LLMPrecompile) RefundGas(gas uint64, logger *tracing.Hooks, reason tracing.GasChangeReason) {
	if logger != nil {
		logger.OnGasChange(0, gas, reason)
	}
}
