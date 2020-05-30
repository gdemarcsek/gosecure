package secretmanager

import (
	"github.com/gdemarcsek/gosecure/pkg/secretmanager/driver"
	"github.com/hashicorp/golang-lru/lru"
)

// SecretManager can be used to access secrets securely
type SecretManager struct {
	d     driver.SecretAccessDriver
	cache *lru.Cache
}

// New creates a new SecretManager with the specified driver
func New(d driver.SecretAccessDriver) *SecretManager {
	return &SecretManager{d, lru.New(32)}
}

// GetSecret retrieves a named secret using the underlying driver. It makes use uf an LRU cache along the way
func (sm *SecretManager) GetSecret(locator string) (string, error) {
	value, found := sm.Get(locator)
	if !found {
		secret, err := d.GetSecret(locator)
		if err != nil {
			return "", err
		}

		sm.cache.Add(locator, secret)
		return secret, nil
	}

	return value, nil
}

// Clear purges the internal cache of SecretManager
func (sm *SecretManager) Clear() {
	sm.cache.Purge()
}
