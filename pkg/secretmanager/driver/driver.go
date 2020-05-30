package driver

// SecretAccessDriver is the required interface for all secret access drivers
type SecretAccessDriver interface {
	GetSecret(locator string) (string, error)
}
