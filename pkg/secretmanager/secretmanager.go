package secretmanager

import (
	"github.com/gdemarcsek/gosecure/pkg/secretmanager/driver"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
)

// SecretManager can be used to access secrets securely
type SecretManager struct {
	d     driver.SecretAccessDriver
	cache *lru.Cache
}

// New creates a new SecretManager with the specified driver
func New(d driver.SecretAccessDriver) (*SecretManager, error) {
	cache, err := lru.New(32)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create secret manager")
	}
	return &SecretManager{d, cache}, nil
}

// GetSecret retrieves a named secret using the underlying driver. It makes use uf an LRU cache along the way
func (sm *SecretManager) GetSecret(locator string) (string, error) {
	value, found := sm.cache.Get(locator)
	if !found {
		secret, err := sm.d.GetSecret(locator)
		if err != nil {
			return "", errors.Wrap(err, "failed to get secret")
		}

		sm.cache.Add(locator, secret)
		return secret, nil
	}

	return value.(string), nil
}

// Clear purges the internal cache of SecretManager
func (sm *SecretManager) Clear() {
	sm.cache.Purge()
}
