// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/internal/llm"
	"github.com/ethereum/go-ethereum/internal/shared"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// Global counter for RPC calls
var rpcCallCounter uint64

// Global counter for execution sequence
var executionSequence uint64

// BalanceChangeReason represents the reason for balance changes
type BalanceChangeReason string

const (
	// EmulatorRefund represents emulator refund
	EmulatorRefund BalanceChangeReason = "emulator_refund"
)

// Backend interface defines the methods required by the emulator API
type Backend interface {
	ChainConfig() *params.ChainConfig
	StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base vm.StateDB, checkLive bool, preferDisk bool) (vm.StateDB, tracers.StateReleaseFunc, error)
	CurrentBlock() *types.Header
	GetEVM(ctx context.Context, msg *core.Message, state vm.StateDB, header *types.Header, vmConfig *vm.Config, blockContext *vm.BlockContext) *vm.EVM
}

// EmulatorBackend interface provides the minimal API services needed for emulator
type EmulatorBackend interface {
	ChainConfig() *params.ChainConfig
	StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base vm.StateDB, checkLive bool, preferDisk bool) (vm.StateDB, tracers.StateReleaseFunc, error)
	CurrentBlock() *types.Header
	GetEVM(ctx context.Context, msg *core.Message, state vm.StateDB, header *types.Header, vmConfig *vm.Config, blockContext *vm.BlockContext) *vm.EVM
}

// EmulatorAPI provides an API to access emulator related information
type EmulatorAPI struct {
	b EmulatorBackend
}

// NewEmulatorAPI creates a new EmulatorAPI instance
func NewEmulatorAPI(b EmulatorBackend) *EmulatorAPI {
	return &EmulatorAPI{b: b}
}

// validateTransaction validates the transaction
func (api *EmulatorAPI) validateTransaction(tx *types.Transaction) error {
	// Get chain configuration
	chainConfig := api.b.ChainConfig()
	if chainConfig == nil {
		return fmt.Errorf("chain configuration is nil")
	}

	// Get sender address
	from, err := types.Sender(types.NewEIP155Signer(chainConfig.ChainID), tx)
	if err != nil {
		return fmt.Errorf("failed to get sender address: %v", err)
	}

	// Validate sender address
	if from == (common.Address{}) {
		return fmt.Errorf("invalid sender address: zero address")
	}

	return nil
}

// submitTransaction submits the transaction
func (api *EmulatorAPI) submitTransaction(tx *types.Transaction) (common.Hash, error) {
	// Return transaction hash
	return tx.Hash(), nil
}

// bytesToHex converts byte array to hexadecimal string
func bytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// hexToBig converts a hex string to a big.Int
func hexToBig(hex string) *big.Int {
	if !strings.HasPrefix(hex, "0x") {
		hex = "0x" + hex
	}
	n := new(big.Int)
	n.SetString(hex[2:], 16)
	return n
}

// getCallParamFromLogs gets _callParam from FeePaid event using eth_getLogs
func (api *EmulatorAPI) getCallParamFromLogs(rpcURL string, txHash common.Hash) (string, error) {
	// 首先确认交易是否已经成功执行
	client := &http.Client{}
	confirmReqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []interface{}{txHash.Hex()},
		"id":      4,
	}
	confirmJsonData, err := json.Marshal(confirmReqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal confirmation request: %v", err)
	}

	confirmResp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(confirmJsonData))
	if err != nil {
		return "", fmt.Errorf("failed to confirm transaction: %v", err)
	}
	defer confirmResp.Body.Close()

	var confirmResult struct {
		Result struct {
			Status string `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&confirmResult); err != nil {
		return "", fmt.Errorf("failed to decode confirmation response: %v", err)
	}

	if confirmResult.Result.Status != "0x1" {
		return "", fmt.Errorf("transaction %s failed or is still pending", txHash.Hex())
	}

	// 继续获取 FeePaid 事件
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getLogs",
		"params": []interface{}{
			map[string]interface{}{
				"fromBlock": "0x0",
				"toBlock":   "latest",
				"topics": []string{
					crypto.Keccak256Hash([]byte("FeePaid(address,uint256,uint256,uint256,bytes)")).Hex(),
				},
				"transactionHash": txHash.Hex(),
			},
		},
		"id": 5,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	fmt.Printf("xxlRPC URL: %s\n", rpcURL)
	fmt.Printf("xxlRequest body: %s\n", string(jsonData))
	resp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Result []struct {
			Data            string   `json:"data"`
			Topics          []string `json:"topics"`
			TransactionHash string   `json:"transactionHash"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// 遍历所有结果，找到对应交易哈希的事件
	for _, log := range result.Result {
		if log.TransactionHash == txHash.Hex() {
			// The _callParam is the last parameter in the event
			// We need to decode the data field to get it
			// The data field contains all non-indexed parameters
			// In this case, only maxOutputLength and callParam are non-indexed parameters
			data := log.Data
			if len(data) < 2 {
				return "", fmt.Errorf("invalid data length")
			}

			// Remove 0x prefix
			data = data[2:]

			// The data field is padded to 32 bytes for each parameter
			// We need to skip the first parameter (maxOutputLength)
			// Each parameter is 64 characters (32 bytes in hex)
			callParamStart := 64
			if len(data) < callParamStart {
				return "", fmt.Errorf("invalid data length for callParam")
			}

			// The callParam is a bytes type, which is encoded as:
			// 1. Offset (32 bytes)
			// 2. Length (32 bytes)
			// 3. Data (padded to 32 bytes)
			// We need to get the length first
			lengthHex := data[callParamStart+64 : callParamStart+128]
			length, err := strconv.ParseInt(lengthHex, 16, 64)
			if err != nil {
				return "", fmt.Errorf("failed to parse callParam length: %v", err)
			}

			// Get the actual callParam data
			// The data starts after the length
			dataStart := callParamStart + 128
			dataEnd := dataStart + int(length*2) // Each byte is 2 hex characters
			if len(data) < dataEnd {
				return "", fmt.Errorf("invalid data length for callParam content")
			}

			callParamHex := data[dataStart:dataEnd]
			callParamBytes, err := hex.DecodeString(callParamHex)
			if err != nil {
				return "", fmt.Errorf("failed to decode callParam: %v", err)
			}

			// Convert bytes to hex string
			return "0x" + hex.EncodeToString(callParamBytes), nil
		}
	}

	return "", fmt.Errorf("no FeePaid event found for transaction %s", txHash.Hex())
}

// SendRawTransaction sends a raw transaction
func (api *EmulatorAPI) SendRawTransaction(ctx context.Context, input hexutil.Bytes) (common.Hash, error) {
	callNum := atomic.AddUint64(&rpcCallCounter, 1)
	fmt.Printf("\nxxlSendRawTransaction Call #%04d ==================\n", callNum)
	seqNum := atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d] SendRawTransaction RPC params:\n", seqNum)
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   Input (hex): %x\n", seqNum, input)

	// Get transaction hash from input
	txHash := common.BytesToHash(input)
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   Transaction hash: %x\n", seqNum, txHash)

	// Set shared hash at the beginning of the function
	shared.SetSharedHash(txHash)

	// Read config file to get RPC URL
	workDir := os.Getenv("workdir")
	fmt.Printf("xxl[%04d]   Workdir: %s\n", seqNum, workDir)
	configPath := filepath.Join(workDir, "config/llmSetting.json")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to read config file: %v", err)
	}

	var config struct {
		PrivateKey string `json:"private_key"`
		RPCURL     string `json:"rpc_url"`
	}
	if err := json.Unmarshal(configData, &config); err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Get _callParam from logs using eth_getLogs
	callParam, err := api.getCallParamFromLogs(config.RPCURL, txHash)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get callParam from logs: %v", err)
	}
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   CallParam: %s\n", seqNum, callParam)

	// Parse callParam
	txParams, err := parseCallParam(callParam)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse callParam: %v", err)
	}
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   Parsed transaction parameters:\n", seqNum)
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]     To: %s\n", seqNum, txParams.To)
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]     Value: %s\n", seqNum, txParams.Value)
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]     Data: %s\n", seqNum, txParams.Data)

	// Build transaction
	nonce, err := api.getNonceFromRPC(config.RPCURL, config.PrivateKey)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get nonce: %v", err)
	}

	gasPrice, err := api.getGasPriceFromRPC(config.RPCURL)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get gas price: %v", err)
	}

	chainID, err := api.getChainIDFromRPC(config.RPCURL)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get chain ID: %v", err)
	}

	// Create transaction
	tx := types.NewTransaction(
		nonce,
		common.HexToAddress(txParams.To),
		hexToBig(txParams.Value),
		800000, // gas limit
		hexToBig(gasPrice),
		common.FromHex(txParams.Data),
	)

	// Sign transaction
	privateKey, err := crypto.HexToECDSA(config.PrivateKey)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse private key: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(chainID)), privateKey)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Save signed transaction data to shared storage
	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to marshal signed transaction: %v", err)
	}
	fmt.Printf("@@@@@@@@ xxl 0000 signedTxBytes (hex): 0x%x\n", hex.EncodeToString(signedTxBytes))
	llm.SetSharedSignedTx(hex.EncodeToString(signedTxBytes))
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d] Signed transaction (hex): 0x%x\n", seqNum, signedTxBytes)

	// Get current block
	block := api.b.CurrentBlock()
	if block == nil {
		return common.Hash{}, fmt.Errorf("failed to get current block")
	}
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   Current block number: %d\n", seqNum, block.Number.Uint64())
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   Current block hash: %x\n", seqNum, block.Hash())

	// Get state database
	statedb, releaseFunc, err := api.b.StateAtBlock(ctx, types.NewBlockWithHeader(block), 0, nil, true, false)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get state at block: %v", err)
	}
	defer releaseFunc()

	// Create EVM config
	vmConfig := vm.Config{}

	// Create block context
	blockContext := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash:     func(n uint64) common.Hash { return common.Hash{} },
		Coinbase:    block.Coinbase,
		BlockNumber: new(big.Int).SetUint64(block.Number.Uint64()),
		Time:        block.Time,
		Difficulty:  new(big.Int).Set(block.Difficulty),
		GasLimit:    block.GasLimit,
		BaseFee:     new(big.Int).Set(block.BaseFee),
	}

	// Create message
	msg := &core.Message{
		From:       crypto.PubkeyToAddress(privateKey.PublicKey),
		To:         signedTx.To(),
		Nonce:      signedTx.Nonce(),
		Value:      signedTx.Value(),
		GasLimit:   signedTx.Gas(),
		GasPrice:   signedTx.GasPrice(),
		GasFeeCap:  signedTx.GasFeeCap(),
		GasTipCap:  signedTx.GasTipCap(),
		Data:       signedTx.Data(),
		AccessList: signedTx.AccessList(),
	}

	// Create EVM instance
	evm := api.b.GetEVM(ctx, msg, statedb, block, &vmConfig, &blockContext)

	// Execute transaction
	result, err := core.ApplyMessage(evm, msg, new(core.GasPool).AddGas(msg.GasLimit))
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to apply message: %v", err)
	}

	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   Transaction execution result:\n", seqNum)
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]     Gas used: %d\n", seqNum, result.UsedGas)
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]     Failed: %v\n", seqNum, result.Failed())
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]     Return value: %x\n", seqNum, result.ReturnData)

	return signedTx.Hash(), nil
}

// parseCallParam parses the callParam string
func parseCallParam(callParam string) (struct {
	To    string
	Value string
	Data  string
}, error) {
	// Remove 0x prefix
	if strings.HasPrefix(callParam, "0x") {
		callParam = callParam[2:]
	}

	// Parse each part
	if len(callParam) < 144 {
		return struct {
			To    string
			Value string
			Data  string
		}{}, fmt.Errorf("callParam too short: %d chars", len(callParam))
	}

	to := "0x" + callParam[:40]
	value := "0x" + callParam[40:104]
	data := "0x" + callParam[104:]

	return struct {
		To    string
		Value string
		Data  string
	}{
		To:    to,
		Value: value,
		Data:  data,
	}, nil
}

// getNonceFromRPC gets nonce from RPC
func (api *EmulatorAPI) getNonceFromRPC(rpcURL, privateKey string) (uint64, error) {
	// Get address from private key
	privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return 0, fmt.Errorf("failed to parse private key: %v", err)
	}
	address := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)

	client := &http.Client{}
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionCount",
		"params":  []string{address.Hex(), "latest"},
		"id":      1,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return 0, err
	}

	resp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	nonce, err := strconv.ParseUint(result.Result[2:], 16, 64)
	if err != nil {
		return 0, err
	}

	return nonce, nil
}

// getGasPriceFromRPC gets gas price from RPC
func (api *EmulatorAPI) getGasPriceFromRPC(rpcURL string) (string, error) {
	client := &http.Client{}
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_gasPrice",
		"params":  []string{},
		"id":      2,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	resp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Result, nil
}

// getChainIDFromRPC gets chain ID from RPC
func (api *EmulatorAPI) getChainIDFromRPC(rpcURL string) (int64, error) {
	client := &http.Client{}
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_chainId",
		"params":  []string{},
		"id":      3,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return 0, err
	}

	resp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	chainID, err := strconv.ParseInt(result.Result[2:], 16, 64)
	if err != nil {
		return 0, err
	}

	return chainID, nil
}

// isValidHexString checks if the string is a valid hexadecimal string
func isValidHexString(s []byte) bool {
	for _, b := range s {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return false
		}
	}
	return true
}

// getRLPType returns the description of RLP data type
func getRLPType(prefix byte) string {
	switch {
	case prefix < 0x80:
		return "single byte"
	case prefix < 0xB8:
		return "short string"
	case prefix < 0xC0:
		return "long string"
	case prefix < 0xF8:
		return "short list"
	default:
		return "long list"
	}
}

// CallArgs represents the arguments for a call.
type CallArgs struct {
	From                 common.Address   `json:"from"`
	To                   *common.Address  `json:"to"`
	Gas                  uint64           `json:"gas"`
	GasPrice             *hexutil.Big     `json:"gasPrice"`
	MaxFeePerGas         *hexutil.Big     `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *hexutil.Big     `json:"maxPriorityFeePerGas"`
	Value                *hexutil.Big     `json:"value"`
	Data                 hexutil.Bytes    `json:"data"`
	AccessList           types.AccessList `json:"accessList,omitempty"`
	BlobHashes           []common.Hash    `json:"blobHashes,omitempty"`
	BlobFeeCap           *hexutil.Big     `json:"blobFeeCap,omitempty"`
	BlobGasFee           *hexutil.Big     `json:"blobGasFee,omitempty"`
	BlobGasUsed          uint64           `json:"blobGasUsed,omitempty"`
	BlobBaseFee          *hexutil.Big     `json:"blobBaseFee,omitempty"`
	BlobDataGasUsed      uint64           `json:"blobDataGasUsed,omitempty"`
}

// StateOverride is the collection of overridden accounts.
type StateOverride map[common.Address]OverrideAccount

// OverrideAccount indicates the overriding fields of account during the execution of
// a message call.
type OverrideAccount struct {
	Nonce     *uint64                      `json:"nonce"`
	Code      *hexutil.Bytes               `json:"code"`
	Balance   **hexutil.Big                `json:"balance"`
	State     *map[common.Hash]common.Hash `json:"state"`
	StateDiff *map[common.Hash]common.Hash `json:"stateDiff"`
}

// ExecutionResult groups all structured logs emitted by the EVM
// while replaying a transaction in debug mode as well as transaction
// execution status, the amount of gas used and the return value
type ExecutionResult struct {
	Gas         uint64      `json:"gas"`
	Failed      bool        `json:"failed"`
	ReturnValue string      `json:"returnValue"`
	StructLogs  []StructLog `json:"structLogs"`
}

// StructLog is emitted to the EVM each cycle and lists information about the current internal state
// prior to the execution of the statement.
type StructLog struct {
	Pc            uint64            `json:"pc"`
	Op            string            `json:"op"`
	Gas           uint64            `json:"gas"`
	GasCost       uint64            `json:"gasCost"`
	Depth         int               `json:"depth"`
	Error         error             `json:"error,omitempty"`
	Stack         []string          `json:"stack"`
	Memory        []string          `json:"memory"`
	Storage       map[string]string `json:"storage"`
	RefundCounter uint64            `json:"refund"`
}

// SimulateCall simulates the execution of an EVM contract without modifying the chain state
func (s *EmulatorAPI) SimulateCall(ctx context.Context, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride) (*ExecutionResult, error) {
	callNum := atomic.AddUint64(&rpcCallCounter, 1)
	fmt.Printf("\nxxlSimulateCall Call #%04d ==================\n", callNum)
	seqNum := atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d] SimulateCall RPC params:\n", seqNum)
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   From: %s\n", seqNum, args.From.Hex())
	if args.To != nil {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   To: %s\n", seqNum, args.To.Hex())
	} else {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   To: nil (contract creation)\n", seqNum)
	}
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   Gas: %d\n", seqNum, args.Gas)
	if args.GasPrice != nil {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   GasPrice: %s\n", seqNum, args.GasPrice.ToInt().String())
	}
	if args.MaxFeePerGas != nil {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   MaxFeePerGas: %s\n", seqNum, args.MaxFeePerGas.ToInt().String())
	}
	if args.MaxPriorityFeePerGas != nil {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   MaxPriorityFeePerGas: %s\n", seqNum, args.MaxPriorityFeePerGas.ToInt().String())
	}
	if args.Value != nil {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   Value: %s\n", seqNum, args.Value.ToInt().String())
	}
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   Data: %x\n", seqNum, args.Data)
	if len(args.AccessList) > 0 {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   AccessList: %v\n", seqNum, args.AccessList)
	}
	if len(args.BlobHashes) > 0 {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   BlobHashes: %v\n", seqNum, args.BlobHashes)
	}
	if args.BlobFeeCap != nil {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   BlobFeeCap: %s\n", seqNum, args.BlobFeeCap.ToInt().String())
	}
	seqNum = atomic.AddUint64(&executionSequence, 1)
	fmt.Printf("xxl[%04d]   BlockNumberOrHash: %v\n", seqNum, blockNrOrHash)
	if overrides != nil {
		seqNum = atomic.AddUint64(&executionSequence, 1)
		fmt.Printf("xxl[%04d]   Overrides: %+v\n", seqNum, *overrides)
	}

	// Get current block
	currentBlock := s.b.CurrentBlock()
	if currentBlock == nil {
		return nil, fmt.Errorf("failed to get current block")
	}
	fmt.Printf("  Current block number: %d\n", currentBlock.Number.Uint64())
	fmt.Printf("  Current block hash: %x\n", currentBlock.Hash())

	// Create a new state database for simulation
	statedb, releaseFunc, err := s.b.StateAtBlock(ctx, types.NewBlockWithHeader(currentBlock), 0, nil, true, false)
	if err != nil {
		log.Error("Failed to get state at block", "error", err)
		return nil, err
	}
	if releaseFunc != nil {
		defer releaseFunc()
	}

	// Apply state overrides
	if overrides != nil {
		fmt.Printf("  Applying state overrides...\n")
		for addr, account := range *overrides {
			fmt.Printf("    Overriding account %s\n", addr.Hex())
			// Set nonce
			if account.Nonce != nil {
				statedb.SetNonce(addr, *account.Nonce)
				fmt.Printf("      Nonce: %d\n", *account.Nonce)
			}
			// Set code
			if account.Code != nil {
				statedb.SetCode(addr, *account.Code)
				fmt.Printf("      Code: %x\n", *account.Code)
			}
			// Set balance
			if account.Balance != nil {
				reason := tracing.BalanceChangeReason(0) // Use default value 0
				balance := (*account.Balance).ToInt()
				statedb.SetBalance(addr, balance, reason)
				fmt.Printf("      Balance: %s\n", (*account.Balance).String())
			}
			// Set state
			if account.State != nil {
				for key, value := range *account.State {
					statedb.SetState(addr, key, value)
					fmt.Printf("      State[%x] = %x\n", key, value)
				}
			}
		}
	}

	// Create EVM config with tracing enabled
	vmConfig := vm.Config{
		Tracer: &tracing.Hooks{},
	}

	// Create block context
	blockContext := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash:     func(n uint64) common.Hash { return common.Hash{} },
		Coinbase:    currentBlock.Coinbase,
		BlockNumber: new(big.Int).SetUint64(currentBlock.Number.Uint64()),
		Time:        currentBlock.Time,
		Difficulty:  new(big.Int).Set(currentBlock.Difficulty),
		GasLimit:    currentBlock.GasLimit,
		BaseFee:     new(big.Int).Set(currentBlock.BaseFee),
	}

	// Create message
	msg := &core.Message{
		From:       args.From,
		To:         args.To,
		Value:      args.Value.ToInt(),
		Nonce:      0,
		GasLimit:   args.Gas,
		GasPrice:   args.GasPrice.ToInt(),
		GasFeeCap:  args.MaxFeePerGas.ToInt(),
		GasTipCap:  args.MaxPriorityFeePerGas.ToInt(),
		Data:       args.Data,
		AccessList: args.AccessList,
	}

	fmt.Printf("  Executing message...\n")
	// Create EVM instance
	evm := s.b.GetEVM(ctx, msg, statedb, currentBlock, &vmConfig, &blockContext)

	// Execute call
	result, err := core.ApplyMessage(evm, msg, new(core.GasPool).AddGas(args.Gas))
	if err != nil {
		log.Error("Failed to apply message", "error", err)
		return nil, err
	}

	fmt.Printf("  Execution completed:\n")
	fmt.Printf("    Gas used: %d\n", result.UsedGas)
	fmt.Printf("    Failed: %v\n", result.Failed())
	fmt.Printf("    Return value: %x\n", result.ReturnData)

	// Get struct logs from tracer
	var structLogs []StructLog
	// 由于 tracing.Hooks 不是接口类型，我们需要使用其他方式来获取日志
	// 暂时返回空的日志列表
	structLogs = []StructLog{}

	// Return execution result
	return &ExecutionResult{
		Gas:         result.UsedGas,
		Failed:      result.Failed(),
		ReturnValue: hex.EncodeToString(result.ReturnData),
		StructLogs:  structLogs,
	}, nil
}

// RegisterEmulatorAPI registers the emulator API with the node
func RegisterEmulatorAPI(stack *node.Node, backend Backend) error {
	if backend == nil {
		return fmt.Errorf("backend is nil")
	}

	// Create new emulator API instance
	api := NewEmulatorAPI(backend)

	// Register the API with the node
	stack.RegisterAPIs([]rpc.API{
		{
			Namespace: "emulator",
			Version:   "1.0",
			Service:   api,
			Public:    true,
		},
	})

	return nil
}
