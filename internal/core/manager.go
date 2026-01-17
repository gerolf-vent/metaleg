package core

type Manager interface {
	Name() string
	Setup() error
	Purge() error
	Reconcile(changes StateChange) error
	Cleanup() error
}
