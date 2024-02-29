// Copyright 2021 The go-ethereum Authors
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

package logger

import (
	"encoding/json"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/directory"
)

type JSONLogger struct {
	directory.NoopTracer
	encoder *json.Encoder
	cfg     *Config
	env     *tracing.VMContext
}

// NewJSONLogger creates a new EVM tracer that prints execution steps as JSON objects
// into the provided stream.
func NewJSONLogger(cfg *Config, writer io.Writer) *JSONLogger {
	l := &JSONLogger{encoder: json.NewEncoder(writer), cfg: cfg}
	if l.cfg == nil {
		l.cfg = &Config{}
	}
	return l
}

func (l *JSONLogger) Hooks() *tracing.Hooks {
	return &tracing.Hooks{
		OnTxStart: l.CaptureTxStart,
		OnEnd:     l.CaptureEnd,
		OnOpcode:  l.CaptureState,
		OnFault:   l.CaptureFault,
	}
}

func (l *JSONLogger) CaptureFault(pc uint64, op tracing.OpCode, gas uint64, cost uint64, scope tracing.OpContext, depth int, err error) {
	// TODO: Add rData to this interface as well
	l.CaptureState(pc, op, gas, cost, scope, nil, depth, err)
}

// CaptureState outputs state information on the logger.
func (l *JSONLogger) CaptureState(pc uint64, op tracing.OpCode, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	memory := scope.MemoryData()
	stack := scope.StackData()

	log := StructLog{
		Pc:            pc,
		Op:            vm.OpCode(op),
		Gas:           gas,
		GasCost:       cost,
		MemorySize:    len(memory),
		Depth:         depth,
		RefundCounter: l.env.StateDB.GetRefund(),
		Err:           err,
	}
	if l.cfg.EnableMemory {
		log.Memory = memory
	}
	if !l.cfg.DisableStack {
		log.Stack = stack
	}
	if l.cfg.EnableReturnData {
		log.ReturnData = rData
	}
	l.encoder.Encode(log)
}

// CaptureEnd is triggered at end of execution.
func (l *JSONLogger) CaptureEnd(output []byte, gasUsed uint64, err error, reverted bool) {
	type endLog struct {
		Output  string              `json:"output"`
		GasUsed math.HexOrDecimal64 `json:"gasUsed"`
		Err     string              `json:"error,omitempty"`
	}
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	l.encoder.Encode(endLog{common.Bytes2Hex(output), math.HexOrDecimal64(gasUsed), errMsg})
}

func (l *JSONLogger) CaptureTxStart(env *tracing.VMContext, tx *types.Transaction, from common.Address) {
	l.env = env
}
