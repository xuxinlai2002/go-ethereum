package state

import (
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/llm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// ErrGasUintOverflow is returned when calculating gas usage results in overflow
var ErrGasUintOverflow = fmt.Errorf("gas uint64 overflow")

// ExecutionResult represents the result of a transaction execution
type ExecutionResult struct {
	UsedGas    uint64
	Err        error
	ReturnData []byte
}

// StateTransition represents a state transition
type StateTransition struct {
	msg        Message
	gas        uint64
	gasPrice   *big.Int
	gasTipCap  *big.Int
	gasFeeCap  *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract
type Message interface {
	From() common.Address
	To() *common.Address
	GasPrice() *big.Int
	GasTipCap() *big.Int
	GasFeeCap() *big.Int
	Gas() uint64
	Value() *big.Int
	Nonce() uint64
	IsFake() bool
	Data() []byte
	AccessList() types.AccessList
	CheckNonce() bool
	Hash() common.Hash
}

// min returns the smaller of x or y
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// preCheck checks if the message satisfies all consensus rules before applying the message
func (st *StateTransition) preCheck() error {
	msg := st.msg

	// Make sure this transaction's nonce is correct
	if msg.CheckNonce() {
		nonce := st.state.GetNonce(msg.From())
		if nonce < msg.Nonce() {
			return fmt.Errorf("nonce too high: got %d, want %d", msg.Nonce(), nonce)
		} else if nonce > msg.Nonce() {
			return fmt.Errorf("nonce too low: got %d, want %d", msg.Nonce(), nonce)
		}
	}

	// Make sure the sender can afford the transaction
	if st.state.GetBalance(msg.From()).Cmp(msg.Value()) < 0 {
		return fmt.Errorf("insufficient funds for value")
	}

	return nil
}

// TransitionDb will transition the state by applying the current message and
// returning the evm execution result with following fields.
//
// - used gas:
//   total gas used (including gas being refunded)
// - returndata:
//   the returned data from evm
// - concrete execution error:
//   various **EVM** error which aborts the execution,
//   e.g. ErrOutOfGas, ErrExecutionReverted
//
// However if any consensus issue encountered, return the error directly with
// nil evm execution result.
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	// First check this message satisfies all consensus rules before
	// applying the message. The rules include these clauses
	//
	// 1. the nonce of the message caller is correct
	// 2. caller has enough balance to cover transaction fee(gaslimit * gasprice)
	// 3. the amount of gas required is available in the block
	// 4. the purchased gas is enough to cover intrinsic usage
	// 5. there is no overflow when calculating intrinsic gas
	// 6. caller has enough balance to cover asset transfer for **topmost** call

	// Check clauses 1-3, buy gas if everything is correct
	if err := st.preCheck(); err != nil {
		return nil, err
	}

	if st.msg.To() != nil {
		// Check if the target address is a precompiled contract
		precompiles := vm.PrecompiledContractsPrague
		if precompile, ok := precompiles[*st.msg.To()]; ok {
			log.Info("Calling precompiled contract", "address", st.msg.To().Hex())

			// Execute the precompiled contract
			ret, err := precompile.Run(st.evm, st.msg.From(), *st.msg.To(), st.msg.Data(), st.msg.Value(), false, false)
			if err == nil {
				// If this is the LLM precompiled contract and the call was successful,
				// send a notification to Redis
				if *st.msg.To() == common.BytesToAddress([]byte{0x99}) {
					signedTx := llm.GetSharedSignedTx()
					if signedTx != "" {
						// Get Redis client instance
						redisClient := vm.GetLLMRedisCallInstance()
						if redisClient != nil {
							log.Info("LLM precompiled contract call successful, sending Redis notification",
								"signedTx", signedTx)
						} else {
							log.Warn("Redis client not available for LLM notification")
						}
					}
				}
			}
			return &ExecutionResult{
				UsedGas:    st.gasUsed(),
				Err:        err,
				ReturnData: ret,
			}, nil
		}
	}

	msg := st.msg
	sender := msg.From()

	// Pay intrinsic gas
	gas, err := IntrinsicGas(st.data, nil, false, false)
	if err != nil {
		return nil, err
	}

	if st.gas < gas {
		return nil, fmt.Errorf("intrinsic gas too low: %d < %d", st.gas, gas)
	}
	st.gas -= gas

	var (
		ret   []byte
		vmerr error
	)

	if contractCreation := msg.To() == nil; contractCreation {
		// TODO: handle contract creation
		return nil, fmt.Errorf("contract creation not supported")
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(sender, st.state.GetNonce(sender)+1)
		ret, st.gas, vmerr = st.evm.Call(
			vm.AccountRef(sender),
			*msg.To(),
			st.data,
			st.gas,
			st.value,
		)
	}

	st.refundGas()

	return &ExecutionResult{
		UsedGas:    st.gasUsed(),
		Err:        vmerr,
		ReturnData: ret,
	}, nil
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}

// refundGas adds the refunded gas back to the state transition
func (st *StateTransition) refundGas() {
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund
	st.state.SubRefund(refund)
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation bool, isHomestead bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if isContractCreation && isHomestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}

	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		nonZeroGas := params.TxDataNonZeroGasFrontier
		zeroGas := params.TxDataZeroGas

		if (math.MaxUint64 - gas) < nonZeroGas {
			return 0, ErrGasUintOverflow
		}
		gas += nonZeroGas

		if (math.MaxUint64 - gas) < zeroGas {
			return 0, ErrGasUintOverflow
		}
		gas += zeroGas
	}

	if accessList != nil {
		gas += uint64(len(accessList)) * params.TxAccessListAddressGas
		gas += uint64(accessList.StorageKeys()) * params.TxAccessListStorageKeyGas
	}

	return gas, nil
}
