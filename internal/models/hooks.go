package models

import "sync"

var (
	findingHookMu    sync.RWMutex
	findingSavedHook func(Finding)
)

func SetFindingSavedHook(hook func(Finding)) {
	findingHookMu.Lock()
	defer findingHookMu.Unlock()
	findingSavedHook = hook
}

func getFindingSavedHook() func(Finding) {
	findingHookMu.RLock()
	defer findingHookMu.RUnlock()
	return findingSavedHook
}
