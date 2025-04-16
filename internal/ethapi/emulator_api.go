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
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// Global counter for RPC calls
var rpcCallCounter uint64

// BalanceChangeReason represents the reason for balance changes
type BalanceChangeReason string

const (
	// EmulatorRefund represents emulator refund
	EmulatorRefund BalanceChangeReason = "emulator_refund"
)

// StateReleaseFunc is a function to release the state
type StateReleaseFunc func()

// EmulatorBackend interface provides the minimal API services needed for emulator
type EmulatorBackend interface {
	ChainConfig() *params.ChainConfig
	StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, checkLive bool, preferDisk bool) (*state.StateDB, StateReleaseFunc, error)
	CurrentBlock() *types.Header
	GetEVM(ctx context.Context, state *state.StateDB, header *types.Header, vmConfig *vm.Config, blockContext *vm.BlockContext) *vm.EVM
	GetTransactionRecipient(ctx context.Context, txHash common.Hash) (common.Address, error)
	GetCallParamFromLogs(ctx context.Context, recipient common.Address) (string, error)
	ExecuteTransaction(ctx context.Context, tx *types.Transaction) (common.Hash, error)
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
	chainConfig := api.b.ChainConfig()
	if chainConfig == nil {
		return fmt.Errorf("chain configuration is nil")
	}

	from, err := types.Sender(types.NewEIP155Signer(chainConfig.ChainID), tx)
	if err != nil {
		return fmt.Errorf("failed to get sender address: %v", err)
	}

	if from == (common.Address{}) {
		return fmt.Errorf("invalid sender address: zero address")
	}

	return nil
}

// submitTransaction submits the transaction
func (api *EmulatorAPI) submitTransaction(tx *types.Transaction) (common.Hash, error) {
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
	client := &http.Client{}
	confirmReqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []string{txHash.Hex()},
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

	for _, log := range result.Result {
		if log.TransactionHash == txHash.Hex() {
			data := log.Data
			if len(data) < 2 {
				return "", fmt.Errorf("invalid data length")
			}

			data = data[2:]
			callParamStart := 64
			if len(data) < callParamStart {
				return "", fmt.Errorf("invalid data length for callParam")
			}

			lengthHex := data[callParamStart+64 : callParamStart+128]
			length, err := strconv.ParseInt(lengthHex, 16, 64)
			if err != nil {
				return "", fmt.Errorf("failed to parse callParam length: %v", err)
			}

			dataStart := callParamStart + 128
			dataEnd := dataStart + int(length*2)
			if len(data) < dataEnd {
				return "", fmt.Errorf("invalid data length for callParam content")
			}

			callParamHex := data[dataStart:dataEnd]
			callParamBytes, err := hex.DecodeString(callParamHex)
			if err != nil {
				return "", fmt.Errorf("failed to decode callParam: %v", err)
			}

			return "0x" + hex.EncodeToString(callParamBytes), nil
		}
	}

	return "", fmt.Errorf("no FeePaid event found for transaction %s", txHash.Hex())
}

// CallArgs represents the arguments for a call
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
}

// ToMessage converts the call arguments to a message
func (args *CallArgs) ToMessage(chainConfig *params.ChainConfig) (*core.Message, error) {
	var msg core.Message
	msg.From = args.From
	msg.To = args.To
	msg.Nonce = 0
	msg.Value = args.Value.ToInt()
	msg.GasLimit = args.Gas
	msg.GasPrice = args.GasPrice.ToInt()
	msg.GasFeeCap = args.MaxFeePerGas.ToInt()
	msg.GasTipCap = args.MaxPriorityFeePerGas.ToInt()
	msg.Data = args.Data
	msg.AccessList = args.AccessList
	msg.SkipAccountChecks = true

	return &msg, nil
}

// StateOverride is the collection of overridden account states
type StateOverride map[common.Address]OverrideAccount

// OverrideAccount is the state override account
type OverrideAccount struct {
	Nonce     *uint64                      `json:"nonce"`
	Code      *hexutil.Bytes               `json:"code"`
	Balance   **hexutil.Big                `json:"balance"`
	State     *map[common.Hash]common.Hash `json:"state"`
	StateDiff *map[common.Hash]common.Hash `json:"stateDiff"`
}

// ExecutionResult represents the result of a call execution
type ExecutionResult struct {
	Gas         uint64      `json:"gas"`
	Failed      bool        `json:"failed"`
	ReturnValue string      `json:"returnValue"`
	StructLogs  []StructLog `json:"structLogs"`
}

// StructLog represents a structured log entry
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

// SimulateCall simulates a call to a contract
func (s *EmulatorAPI) SimulateCall(ctx context.Context, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride) (*ExecutionResult, error) {
	// Get the state and header
	state, release, err := s.b.StateAtBlock(ctx, nil, 0, nil, true, false)
	if err != nil {
		return nil, err
	}
	if release != nil {
		defer release()
	}

	header := s.b.CurrentBlock()
	if header == nil {
		return nil, fmt.Errorf("current block not found")
	}

	// Create a new EVM
	evm := s.b.GetEVM(ctx, state, header, &vm.Config{}, &vm.BlockContext{})

	// Execute the call
	msg, err := args.ToMessage(evm.ChainConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create message: %v", err)
	}

	result, err := core.ApplyMessage(evm, msg, new(core.GasPool).AddGas(args.Gas))
	if err != nil {
		return nil, err
	}

	// Create the execution result
	executionResult := &ExecutionResult{
		Gas:         result.UsedGas,
		Failed:      result.Failed(),
		ReturnValue: hexutil.Encode(result.ReturnData),
	}

	return executionResult, nil
}

// RegisterEmulatorAPI registers the emulator API with the node
func RegisterEmulatorAPI(stack *node.Node) {
	stack.RegisterAPIs([]rpc.API{
		{
			Namespace: "emulator",
			Service:   NewEmulatorAPI(nil),
		},
	})
}
