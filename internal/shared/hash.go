package shared

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

var (
	sharedHash     common.Hash
	sharedHashLock sync.RWMutex
)

// GetSharedHash returns the current shared hash value
func GetSharedHash() common.Hash {
	sharedHashLock.RLock()
	defer sharedHashLock.RUnlock()
	return sharedHash
}

// SetSharedHash sets the shared hash value
func SetSharedHash(hash common.Hash) {
	sharedHashLock.Lock()
	defer sharedHashLock.Unlock()
	sharedHash = hash
}
