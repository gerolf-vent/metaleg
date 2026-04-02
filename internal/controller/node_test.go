package controller

import (
	"context"
	"testing"
	"time"

	"github.com/gerolf-vent/metaleg/internal/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
)

func startNodeController(t *testing.T, reconciler *mock.Reconciler) client.Client {
	t.Helper()

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: testScheme,
		Controller: config.Controller{
			SkipNameValidation: ptr.To(true),
		},
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	if err := AttachNodeController(mgr, reconciler, NodeAddressTypeInternal); err != nil {
		t.Fatalf("Failed to attach node controller: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Errorf("Manager exited with error: %v", err)
		}
	}()

	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("Cache never synced")
	}

	return mgr.GetClient()
}

func waitForReconciler(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Timed out waiting for reconciler condition")
}

func TestNodeController_CreateNode(t *testing.T) {
	r := mock.NewReconciler()
	k := startNodeController(t, r)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test-node-create"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeInternalIP, Address: "fd00::1"},
			},
		},
	}

	if err := k.Create(context.Background(), node); err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), node) })

	// Update status (envtest doesn't apply status on create)
	node.Status = corev1.NodeStatus{
		Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			{Type: corev1.NodeInternalIP, Address: "fd00::1"},
		},
	}
	if err := k.Status().Update(context.Background(), node); err != nil {
		t.Fatalf("Failed to update node status: %v", err)
	}

	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.UpdateNodeCalls {
			if c.Name == "test-node-create" {
				return true
			}
		}
		return false
	})

	var found bool
	for _, c := range r.UpdateNodeCalls {
		if c.Name == "test-node-create" {
			found = true
			if c.IPv4 == nil || c.IPv4.String() != "10.0.0.1" {
				t.Errorf("Expected IPv4 10.0.0.1, got %v", c.IPv4)
			}
			if c.IPv6 == nil || c.IPv6.String() != "fd00::1" {
				t.Errorf("Expected IPv6 fd00::1, got %v", c.IPv6)
			}
		}
	}
	if !found {
		t.Error("Expected UpdateNode call for test-node-create")
	}
}

func TestNodeController_DeleteNode(t *testing.T) {
	r := mock.NewReconciler()
	k := startNodeController(t, r)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test-node-delete"},
	}

	if err := k.Create(context.Background(), node); err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	waitForReconciler(t, 5*time.Second, func() bool {
		return len(r.UpdateNodeCalls) > 0
	})

	if err := k.Delete(context.Background(), node); err != nil {
		t.Fatalf("Failed to delete node: %v", err)
	}

	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.DeleteNodeCalls {
			if c == "test-node-delete" {
				return true
			}
		}
		return false
	})
}

func TestNodeController_UpdateNodeIP(t *testing.T) {
	r := mock.NewReconciler()
	k := startNodeController(t, r)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test-node-update"},
	}

	if err := k.Create(context.Background(), node); err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), node) })

	waitForReconciler(t, 5*time.Second, func() bool {
		return len(r.UpdateNodeCalls) > 0
	})

	// Update the node status with an IP
	node.Status = corev1.NodeStatus{
		Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "10.0.0.99"},
		},
	}
	if err := k.Status().Update(context.Background(), node); err != nil {
		t.Fatalf("Failed to update node status: %v", err)
	}

	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.UpdateNodeCalls {
			if c.Name == "test-node-update" && c.IPv4 != nil && c.IPv4.String() == "10.0.0.99" {
				return true
			}
		}
		return false
	})
}

func TestNodeController_NodeWithNoInternalIP(t *testing.T) {
	r := mock.NewReconciler()
	k := startNodeController(t, r)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test-node-noip"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "203.0.113.1"},
			},
		},
	}

	if err := k.Create(context.Background(), node); err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), node) })

	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.UpdateNodeCalls {
			if c.Name == "test-node-noip" {
				return true
			}
		}
		return false
	})

	for _, c := range r.UpdateNodeCalls {
		if c.Name == "test-node-noip" {
			if c.IPv4 != nil {
				t.Errorf("Expected nil IPv4 for node with no internal IP, got %v", c.IPv4)
			}
			if c.IPv6 != nil {
				t.Errorf("Expected nil IPv6 for node with no internal IP, got %v", c.IPv6)
			}
		}
	}
}
