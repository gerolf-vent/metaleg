package mock

import (
	"context"

	"github.com/gerolf-vent/metaleg/internal/core"
)

type Reconciler struct {
	StartFunc            func(ctx context.Context) error
	PurgeFunc            func() error
	IsReadyVal           bool
	UpdateEgressRuleFunc func(egressRule core.EgressRule) error
	DeleteEgressRuleFunc func(id string) error
	UpdateNodeFunc       func(node core.Node) error
	DeleteNodeFunc       func(nodeName string) error

	UpdateEgressRuleCalls []core.EgressRule
	DeleteEgressRuleCalls []string
	UpdateNodeCalls       []core.Node
	DeleteNodeCalls       []string
}

func NewReconciler() *Reconciler {
	return &Reconciler{IsReadyVal: true}
}

func (r *Reconciler) Start(ctx context.Context) error {
	if r.StartFunc != nil {
		return r.StartFunc(ctx)
	}
	return nil
}

func (r *Reconciler) Purge() error {
	if r.PurgeFunc != nil {
		return r.PurgeFunc()
	}
	return nil
}

func (r *Reconciler) IsReady() bool {
	return r.IsReadyVal
}

func (r *Reconciler) UpdateEgressRule(egressRule core.EgressRule) error {
	r.UpdateEgressRuleCalls = append(r.UpdateEgressRuleCalls, egressRule)
	if r.UpdateEgressRuleFunc != nil {
		return r.UpdateEgressRuleFunc(egressRule)
	}
	return nil
}

func (r *Reconciler) DeleteEgressRule(id string) error {
	r.DeleteEgressRuleCalls = append(r.DeleteEgressRuleCalls, id)
	if r.DeleteEgressRuleFunc != nil {
		return r.DeleteEgressRuleFunc(id)
	}
	return nil
}

func (r *Reconciler) UpdateNode(node core.Node) error {
	r.UpdateNodeCalls = append(r.UpdateNodeCalls, node)
	if r.UpdateNodeFunc != nil {
		return r.UpdateNodeFunc(node)
	}
	return nil
}

func (r *Reconciler) DeleteNode(nodeName string) error {
	r.DeleteNodeCalls = append(r.DeleteNodeCalls, nodeName)
	if r.DeleteNodeFunc != nil {
		return r.DeleteNodeFunc(nodeName)
	}
	return nil
}
