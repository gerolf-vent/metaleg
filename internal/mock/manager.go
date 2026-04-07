package mock

import "github.com/gerolf-vent/metaleg/internal/core"

type Manager struct {
	NameVal        string
	SetupFunc      func() error
	PurgeFunc      func() error
	ReconcileFunc  func(core.StateChange) error
	CleanupFunc    func() error
	ReconcileCalls []core.StateChange
}

func NewManager(name string) *Manager {
	return &Manager{NameVal: name}
}

func (m *Manager) Name() string { return m.NameVal }

func (m *Manager) Setup() error {
	if m.SetupFunc != nil {
		return m.SetupFunc()
	}
	return nil
}

func (m *Manager) Purge() error {
	if m.PurgeFunc != nil {
		return m.PurgeFunc()
	}
	return nil
}

func (m *Manager) Reconcile(change core.StateChange) error {
	m.ReconcileCalls = append(m.ReconcileCalls, change)
	if m.ReconcileFunc != nil {
		return m.ReconcileFunc(change)
	}
	return nil
}

func (m *Manager) Cleanup() error {
	if m.CleanupFunc != nil {
		return m.CleanupFunc()
	}
	return nil
}
