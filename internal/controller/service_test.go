package controller

import (
	"context"
	"testing"
	"time"

	"github.com/gerolf-vent/metaleg/internal/mock"
	metallbv1beta1 "go.universe.tf/metallb/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
)

func startServiceController(t *testing.T, reconciler *mock.Reconciler, config *Config) client.Client {
	t.Helper()

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: testScheme,
		Controller: ctrlconfig.Controller{
			SkipNameValidation: ptr.To(true),
		},
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	if err := AttachServiceController(mgr, reconciler, config); err != nil {
		t.Fatalf("Failed to attach service controller: %v", err)
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

func ensureNamespace(t *testing.T, k client.Client, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k.Create(context.Background(), ns); err != nil {
		// Ignore already-exists
		if client.IgnoreAlreadyExists(err) != nil {
			t.Fatalf("Failed to create namespace %s: %v", name, err)
		}
	}
}

func svcConfig(nodeName, mlbNS string, filterForNode bool) *Config {
	return &Config{
		NodeName:               nodeName,
		MLBNamespace:           mlbNS,
		FilterEndpointsForNode: filterForNode,
	}
}

func TestServiceController_CreateLabeledService(t *testing.T) {
	r := mock.NewReconciler()
	config := svcConfig("local-node", "metallb-system", false)
	k := startServiceController(t, r, config)

	ns := "svc-test-create"
	ensureNamespace(t, k, ns)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: ns,
			Labels:    map[string]string{labelRewriteSourceIP: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}
	if err := k.Create(context.Background(), svc); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), svc) })

	// Assign LB IP via status
	svc.Status = corev1.ServiceStatus{
		LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{{IP: "1.2.3.4"}},
		},
	}
	if err := k.Status().Update(context.Background(), svc); err != nil {
		t.Fatalf("Failed to update service status: %v", err)
	}

	// Create an EndpointSlice
	epSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-abc",
			Namespace: ns,
			Labels:    map[string]string{discoveryv1.LabelServiceName: "web"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.10"}},
		},
	}
	if err := k.Create(context.Background(), epSlice); err != nil {
		t.Fatalf("Failed to create endpointslice: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), epSlice) })

	// Create MetalLB ServiceL2Status
	ensureNamespace(t, k, "metallb-system")
	sl2s := &metallbv1beta1.ServiceL2Status{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-status",
			Namespace: "metallb-system",
			Labels: map[string]string{
				labelMLBServiceName:      "web",
				labelMLBServiceNamespace: ns,
			},
		},
	}
	if err := k.Create(context.Background(), sl2s); err != nil {
		t.Fatalf("Failed to create ServiceL2Status: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), sl2s) })

	// Patch status with node assignment
	sl2s.Status = metallbv1beta1.MetalLBServiceL2Status{
		Node:             "gw-node",
		ServiceName:      "web",
		ServiceNamespace: ns,
	}
	if err := k.Status().Update(context.Background(), sl2s); err != nil {
		t.Fatalf("Failed to update ServiceL2Status status: %v", err)
	}

	key := ns + "/web"
	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.UpdateEgressRuleCalls {
			if c.ID == key && c.SNATIPv4 != nil && len(c.SrcIPv4s) > 0 && c.GWNodeName == "gw-node" {
				return true
			}
		}
		return false
	})

	var found bool
	for _, c := range r.UpdateEgressRuleCalls {
		if c.ID == key && c.SNATIPv4 != nil && c.SNATIPv4.String() == "1.2.3.4" && c.GWNodeName == "gw-node" {
			found = true
			if len(c.SrcIPv4s) == 0 || c.SrcIPv4s[0].String() != "10.0.0.10" {
				t.Errorf("Expected SrcIPv4 10.0.0.10, got %v", c.SrcIPv4s)
			}
			if c.GWNodeName != "gw-node" {
				t.Errorf("Expected GWNodeName gw-node, got %q", c.GWNodeName)
			}
		}
	}
	if !found {
		t.Error("Expected UpdateEgressRule call with LB IP 1.2.3.4")
	}
}

func TestServiceController_ServiceWithoutLabel(t *testing.T) {
	r := mock.NewReconciler()
	config := svcConfig("local-node", "metallb-system", false)
	k := startServiceController(t, r, config)

	ns := "svc-test-nolabel"
	ensureNamespace(t, k, ns)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-label",
			Namespace: ns,
			// No rewriteSrcIP label
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}
	if err := k.Create(context.Background(), svc); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), svc) })

	key := ns + "/no-label"
	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.DeleteEgressRuleCalls {
			if c == key {
				return true
			}
		}
		return false
	})

	// Verify no UpdateEgressRule was called
	for _, c := range r.UpdateEgressRuleCalls {
		if c.ID == key {
			t.Error("Expected no UpdateEgressRule for service without label")
		}
	}
}

func TestServiceController_DeleteService(t *testing.T) {
	r := mock.NewReconciler()
	config := svcConfig("local-node", "metallb-system", false)
	k := startServiceController(t, r, config)

	ns := "svc-test-delete"
	ensureNamespace(t, k, ns)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "to-delete",
			Namespace: ns,
			Labels:    map[string]string{labelRewriteSourceIP: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}
	if err := k.Create(context.Background(), svc); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), svc) })

	// Wait for initial reconcile
	key := ns + "/to-delete"
	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.DeleteEgressRuleCalls {
			if c == key {
				return true
			}
		}
		return false
	})

	// Reset and delete
	r.DeleteEgressRuleCalls = nil
	if err := k.Delete(context.Background(), svc); err != nil {
		t.Fatalf("Failed to delete service: %v", err)
	}

	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.DeleteEgressRuleCalls {
			if c == key {
				return true
			}
		}
		return false
	})
}

func TestServiceController_ServiceNoEndpoints(t *testing.T) {
	r := mock.NewReconciler()
	config := svcConfig("local-node", "metallb-system", false)
	k := startServiceController(t, r, config)

	ns := "svc-test-noep"
	ensureNamespace(t, k, ns)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-ep",
			Namespace: ns,
			Labels:    map[string]string{labelRewriteSourceIP: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}
	if err := k.Create(context.Background(), svc); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), svc) })

	// Give LB IP but no endpoints
	svc.Status = corev1.ServiceStatus{
		LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{{IP: "5.6.7.8"}},
		},
	}
	if err := k.Status().Update(context.Background(), svc); err != nil {
		t.Fatalf("Failed to update service status: %v", err)
	}

	key := ns + "/no-ep"
	// Should get a delete call since there are no endpoint slices
	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.DeleteEgressRuleCalls {
			if c == key {
				return true
			}
		}
		return false
	})

	for _, c := range r.UpdateEgressRuleCalls {
		if c.ID == key {
			t.Error("Expected no UpdateEgressRule for service without endpoints")
		}
	}
}

func TestServiceController_DualStackService(t *testing.T) {
	r := mock.NewReconciler()
	config := svcConfig("local-node", "metallb-system", false)
	k := startServiceController(t, r, config)

	ns := "svc-test-dualstack"
	ensureNamespace(t, k, ns)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dual",
			Namespace: ns,
			Labels:    map[string]string{labelRewriteSourceIP: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}
	if err := k.Create(context.Background(), svc); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), svc) })

	svc.Status = corev1.ServiceStatus{
		LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{
				{IP: "1.2.3.4"},
				{IP: "fd00::100"},
			},
		},
	}
	if err := k.Status().Update(context.Background(), svc); err != nil {
		t.Fatalf("Failed to update service status: %v", err)
	}

	// IPv4 EndpointSlice
	epv4 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dual-v4",
			Namespace: ns,
			Labels:    map[string]string{discoveryv1.LabelServiceName: "dual"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.20"}}},
	}
	if err := k.Create(context.Background(), epv4); err != nil {
		t.Fatalf("Failed to create IPv4 endpointslice: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), epv4) })

	// IPv6 EndpointSlice
	epv6 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dual-v6",
			Namespace: ns,
			Labels:    map[string]string{discoveryv1.LabelServiceName: "dual"},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"fd00::20"}}},
	}
	if err := k.Create(context.Background(), epv6); err != nil {
		t.Fatalf("Failed to create IPv6 endpointslice: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), epv6) })

	key := ns + "/dual"
	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.UpdateEgressRuleCalls {
			if c.ID == key && c.SNATIPv4 != nil && c.SNATIPv6 != nil && len(c.SrcIPv4s) > 0 && len(c.SrcIPv6s) > 0 {
				return true
			}
		}
		return false
	})

	var found bool
	for _, c := range r.UpdateEgressRuleCalls {
		if c.ID == key && c.SNATIPv4 != nil && c.SNATIPv6 != nil && len(c.SrcIPv4s) > 0 && len(c.SrcIPv6s) > 0 {
			found = true
			if c.SNATIPv4.String() != "1.2.3.4" {
				t.Errorf("Expected SNATIPv4 1.2.3.4, got %v", c.SNATIPv4)
			}
			if c.SNATIPv6.String() != "fd00::100" {
				t.Errorf("Expected SNATIPv6 fd00::100, got %v", c.SNATIPv6)
			}
			if c.SrcIPv4s[0].String() != "10.0.0.20" {
				t.Errorf("Expected SrcIPv4 10.0.0.20, got %v", c.SrcIPv4s[0])
			}
			if c.SrcIPv6s[0].String() != "fd00::20" {
				t.Errorf("Expected SrcIPv6 fd00::20, got %v", c.SrcIPv6s[0])
			}
		}
	}
	if !found {
		t.Error("Expected UpdateEgressRule call with dual-stack IPs")
	}
}

func TestServiceController_FilterEndpointsForNode(t *testing.T) {
	r := mock.NewReconciler()
	config := svcConfig("local-node", "metallb-system", true) // filtering enabled
	k := startServiceController(t, r, config)

	ns := "svc-test-filter"
	ensureNamespace(t, k, ns)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "filtered",
			Namespace: ns,
			Labels:    map[string]string{labelRewriteSourceIP: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}
	if err := k.Create(context.Background(), svc); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), svc) })

	svc.Status = corev1.ServiceStatus{
		LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{{IP: "9.8.7.6"}},
		},
	}
	if err := k.Status().Update(context.Background(), svc); err != nil {
		t.Fatalf("Failed to update service status: %v", err)
	}

	localNode := "local-node"
	otherNode := "other-node"
	epSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "filtered-eps",
			Namespace: ns,
			Labels:    map[string]string{discoveryv1.LabelServiceName: "filtered"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.30"}, NodeName: &localNode},
			{Addresses: []string{"10.0.0.31"}, NodeName: &otherNode},
		},
	}
	if err := k.Create(context.Background(), epSlice); err != nil {
		t.Fatalf("Failed to create endpointslice: %v", err)
	}
	t.Cleanup(func() { k.Delete(context.Background(), epSlice) })

	key := ns + "/filtered"
	waitForReconciler(t, 5*time.Second, func() bool {
		for _, c := range r.UpdateEgressRuleCalls {
			if c.ID == key && len(c.SrcIPv4s) > 0 {
				return true
			}
		}
		return false
	})

	// Find the last matching call (most up-to-date)
	var lastCall *struct {
		srcIPv4s []string
	}
	for i := len(r.UpdateEgressRuleCalls) - 1; i >= 0; i-- {
		c := r.UpdateEgressRuleCalls[i]
		if c.ID == key && len(c.SrcIPv4s) > 0 {
			ips := make([]string, len(c.SrcIPv4s))
			for j, ip := range c.SrcIPv4s {
				ips[j] = ip.String()
			}
			lastCall = &struct{ srcIPv4s []string }{srcIPv4s: ips}
			break
		}
	}
	if lastCall == nil {
		t.Fatal("Expected UpdateEgressRule call with SrcIPv4s")
	}

	// Should contain only the local endpoint (10.0.0.30)
	if len(lastCall.srcIPv4s) != 1 || lastCall.srcIPv4s[0] != "10.0.0.30" {
		t.Errorf("Expected only local endpoint 10.0.0.30, got %v", lastCall.srcIPv4s)
	}
}
