package vm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/redis/go-redis/v9"
)

// Message represents a chat message structure
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// RequestPayload represents the request structure for LLM API
type RequestPayload struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
	Stream      bool      `json:"stream"`
}

// LLMConfig represents the configuration from llmSetting.json
type LLMConfig struct {
	RedisIP       string `json:"redis_ip"`
	RedisPort     int    `json:"redis_port"`
	RedisPassword string `json:"redis_password"`
	ModelID       string `json:"model_id"`
}

var llmConfig LLMConfig

func init() {
	// 读取配置文件
	configFile, err := os.ReadFile("llmSetting.json")
	if err != nil {
		log.Error("Failed to read config file", "error", err)
		return
	}

	if err := json.Unmarshal(configFile, &llmConfig); err != nil {
		log.Error("Failed to parse config file", "error", err)
		return
	}

	log.Info("Loaded LLM configuration", "config", llmConfig)
}

// RedisClient returns the Redis client instance
func RedisClient() *redis.ClusterClient {
	return redisClient
}

// StreamResponse represents the streaming response structure from LLM API
type StreamResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		Index int `json:"index"`
	} `json:"choices"`
}

// Redis client instance
var redisClient *redis.ClusterClient

// InitializeRedisClient initializes the Redis client
func InitializeRedisClient() error {
	// 获取当前工作目录
	fmt.Println("#### xxl 0005 InitializeRedisClient")
	workDir, err := os.Getwd()
	if err != nil {
		log.Error("Failed to get working directory", "error", err)
		return err
	}

	fmt.Println("#### xxl 0001 workDir", "workDir", workDir)
	// 读取配置文件
	configPath := filepath.Join(workDir, "config", "llmSetting.json")
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		log.Error("Failed to read config file", "path", configPath, "error", err)
		return err
	}

	fmt.Println("#### xxl 0002 configFile", "configFile", configFile)
	var config LLMConfig
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Error("Failed to parse config file", "error", err)
		return err
	}

	fmt.Println("#### xxl 0003 config", "config", config)
	// 验证配置
	if config.RedisIP == "" {
		log.Error("Redis IP is not configured")
		return fmt.Errorf("Redis IP is not configured")
	}
	if config.RedisPort == 0 {
		log.Error("Redis port is not configured")
		return fmt.Errorf("Redis port is not configured")
	}

	fmt.Println("#### xxl 0004 redisClient")
	// 创建Redis客户端
	var addresses []string
	for _, port := range []int{7001, 7002, 7003} {
		addr := fmt.Sprintf("%s:%d", config.RedisIP, port)
		addresses = append(addresses, addr)
	}

	fmt.Println("#### xxl 0005 Redis addresses:", "addresses", addresses)

	// 创建 Redis 集群客户端
	redisClient = redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:    addresses,
		Password: config.RedisPassword,
		// 添加集群特定选项
		ReadOnly:       false, // 禁用只读模式
		RouteByLatency: true,  // 根据延迟选择节点
		RouteRandomly:  true,  // 随机选择节点
		MaxRedirects:   3,     // 最大重定向次数
		// 添加超时设置
		DialTimeout:  10 * time.Second, // 增加连接超时时间
		ReadTimeout:  5 * time.Second,  // 增加读取超时时间
		WriteTimeout: 5 * time.Second,  // 增加写入超时时间
		PoolSize:     10,
		MinIdleConns: 3,
		// 添加集群发现选项
		ClusterSlots: func(ctx context.Context) ([]redis.ClusterSlot, error) {
			// 手动定义槽位分配
			return []redis.ClusterSlot{
				{
					Start: 0,
					End:   5460,
					Nodes: []redis.ClusterNode{
						{Addr: fmt.Sprintf("%s:7001", config.RedisIP)},
					},
				},
				{
					Start: 5461,
					End:   10922,
					Nodes: []redis.ClusterNode{
						{Addr: fmt.Sprintf("%s:7002", config.RedisIP)},
					},
				},
				{
					Start: 10923,
					End:   16383,
					Nodes: []redis.ClusterNode{
						{Addr: fmt.Sprintf("%s:7003", config.RedisIP)},
					},
				},
			}, nil
		},
	})

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // 增加上下文超时时间
	defer cancel()

	// 尝试连接到每个节点
	var lastErr error
	for _, addr := range addresses {
		log.Info("Trying to connect to Redis node", "address", addr)
		_, err := redisClient.Ping(ctx).Result()
		if err == nil {
			log.Info("Successfully connected to Redis cluster", "address", addr)
			return nil
		}
		lastErr = err
		log.Error("Failed to connect to Redis node", "address", addr, "error", err)
	}

	return fmt.Errorf("failed to connect to any Redis node: %v", lastErr)
}

// GetSharedHash returns a shared hash for Redis key generation
func GetSharedHash() common.Hash {
	// For now, we'll use a fixed hash. In a real implementation,
	// this should be generated based on the transaction or block context.
	return common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
}

// realCallLLM calls the LLM API with streaming and Redis integration
func realCallLLM(inputText, modelID string, maxOutputLength uint64) string {

	fmt.Println("### xxl 0003 realCallLLM 00 ", "inputText", inputText, "modelID", modelID, "maxOutputLength", maxOutputLength)
	// init redis client
	if err := InitializeRedisClient(); err != nil {
		log.Error("Failed to initialize Redis client", "error", err)
		return fmt.Sprintf("Error: Failed to initialize Redis client: %v", err)
	}

	// check if redis client is initialized
	if redisClient == nil {
		log.Error("Redis client is not initialized")
		return "Error: Redis client is not initialized"
	}

	// get shared hash
	hash := GetSharedHash()
	redisKey := fmt.Sprintf("preExecV2_%x", hash)

	log.Info("LLM call started", "redisKey", redisKey)
	fmt.Println("#### xxl 0001 realCallLLM LLM call started", "redisKey", redisKey)
	// API endpoint
	apiURL := "https://aihubmix.com/v1/chat/completions"

	// Prepare request payload
	payload := RequestPayload{
		Model: modelID,
		Messages: []Message{
			{
				Role:    "user",
				Content: inputText,
			},
		},
		MaxTokens:   int(maxOutputLength),
		Temperature: 0.0,
		Stream:      true,
	}

	fmt.Println("#### xxl 0001 LLM call payload", "payload", payload)
	// Convert payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf("Error marshaling payload: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Sprintf("Error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-w9YvHgmz20vqbLut486d3a3229034aE3B5886f3329Aa3c39")
	req.Header.Set("Accept", "text/event-stream")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Second * 30,
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Sprintf("API error: %s", string(body))
	}

	// Process streaming response
	reader := bufio.NewReader(resp.Body)
	ctx := context.Background()
	var fullResponse strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Error("Error reading response stream", "error", err)
			break
		}

		if line == "" || line == "\n" {
			continue
		}

		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			data = strings.TrimSpace(data)

			if data == "[DONE]" || strings.Contains(data, "[DONE]") {
				// 写入[DONE]标记到Redis
				var err error
				for i := 0; i < 3; i++ {
					err = redisClient.RPush(ctx, redisKey, "[DONE]").Err()
					if err == nil {
						break
					}
					log.Warn("Retry storing [DONE] in Redis", "attempt", i+1, "error", err)
					time.Sleep(time.Millisecond * 100)
				}
				if err != nil {
					log.Error("Failed to store [DONE] in Redis after retries", "error", err)
				}
				continue
			}

			var streamResp StreamResponse
			if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
				log.Error("Error parsing stream response", "error", err, "data", data)
				continue
			}

			// Process stream response and store in Redis
			if len(streamResp.Choices) > 0 {
				content := streamResp.Choices[0].Delta.Content
				if content != "" {
					fmt.Println("#### xxl 0002 LLM call content", "content", content)
					// Append to Redis list with retry mechanism
					var err error
					for i := 0; i < 3; i++ {
						err = redisClient.RPush(ctx, redisKey, content).Err()
						if err == nil {
							break
						}
						log.Warn("Retry storing in Redis", "attempt", i+1, "error", err)
						time.Sleep(time.Millisecond * 100)
					}
					if err != nil {
						log.Error("Failed to store in Redis after retries", "error", err)
					}
					fullResponse.WriteString(content)
				}
			}
		}
	}

	// Set expiration for Redis key (optional)
	redisClient.Expire(ctx, redisKey, time.Hour*24)

	return fullResponse.String()
}
