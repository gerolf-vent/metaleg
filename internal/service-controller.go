package metaleg

import (
	"context"
	"net"

	es "github.com/gerolf-vent/metaleg/internal/egress-service"
	metallbv1beta1 "go.universe.tf/metallb/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	labelRewriteSourceIP     = "metaleg.de/rewriteSrcIP"
	labelMLBServiceName      = "metallb.io/service-name"
	labelMLBServiceNamespace = "metallb.io/service-namespace"
)

type serviceController struct {
	client        client.Client
	es            *es.EgressService
	mlbNamespace  string
	nodeName      string
	filterForNode bool
}

func AttachServiceController(mgr ctrl.Manager, es *es.EgressService, mlbNamespace string, nodeName string, filterForNode bool) error {
	c := &serviceController{
		client:        mgr.GetClient(),
		es:            es,
		mlbNamespace:  mlbNamespace,
		nodeName:      nodeName,
		filterForNode: filterForNode,
	}

	// EndpointSlice -> Service mapper
	mapSlice := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		slice, ok := o.(*discoveryv1.EndpointSlice)
		if !ok {
			return nil
		}
		name, exists := slice.Labels[discoveryv1.LabelServiceName]
		if !exists || name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: slice.Namespace, Name: name}}}
	})

	// MetalLB status -> Service mapper
	mapSL2S := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		sl2s, ok := o.(*metallbv1beta1.ServiceL2Status)
		if !ok {
			return nil
		}
		return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: sl2s.Status.ServiceNamespace, Name: sl2s.Status.ServiceName}}}
	})

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(&discoveryv1.EndpointSlice{}, mapSlice).
		Watches(&metallbv1beta1.ServiceL2Status{}, mapSL2S).
		Complete(c); err != nil {
		return err
	}

	return nil
}

func (c *serviceController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.LoggerFrom(ctx)
	logger.Info("Reconciling Service")

	// Fetch the Service object
	svc := &corev1.Service{}
	if err := c.client.Get(ctx, req.NamespacedName, svc); err != nil {
		if apierrors.IsNotFound(err) {
			// If the service is not found, remove any egress rules associated with it
			err2 := c.es.DeleteEgressRule(req.NamespacedName.String())
			if err2 != nil {
				logger.Error(err2, "Failed to delete egress rule from egress service")
				return ctrl.Result{}, err2
			}
			logger.Info("Service reconciled successfully", "state", "absent", "reason", "object not found")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Service from K8s API")
		return ctrl.Result{}, err
	}

	if rewriteSrcIP, ok := svc.Labels[labelRewriteSourceIP]; !ok || rewriteSrcIP != "true" {
		// If the service does not have the rewriteSrcIP label, remove any egress rules associated with it
		err := c.es.DeleteEgressRule(req.NamespacedName.String())
		if err != nil {
			logger.Error(err, "Failed to delete egress rule from egress service")
			return ctrl.Result{}, err
		}
		logger.Info("Service reconciled successfully", "state", "absent", "reason", "label not set")
		return ctrl.Result{}, nil
	}

	// Fetch the EndpointSlice for this service
	slices := &discoveryv1.EndpointSliceList{}
	if err := c.client.List(ctx, slices, client.InNamespace(req.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: req.Name}); err != nil {
		return ctrl.Result{}, err
	}

	if len(slices.Items) == 0 {
		err := c.es.DeleteEgressRule(req.NamespacedName.String())
		if err != nil {
			logger.Error(err, "Failed to delete egress rule from egress service")
			return ctrl.Result{}, err
		}
		logger.Info("Service reconciled successfully", "state", "absent", "reason", "no endpoint slices found")
		return ctrl.Result{}, nil
	}

	// Fetch the MetalLB ServiceL2Status for this service
	sl2s := &metallbv1beta1.ServiceL2StatusList{}
	if err := c.client.List(ctx, sl2s, client.InNamespace(c.mlbNamespace), client.MatchingLabels{labelMLBServiceNamespace: req.Namespace, labelMLBServiceName: req.Name}); err != nil {
		logger.Error(err, "Failed to list ServiceL2Status for Service")
		return ctrl.Result{}, err
	}

	// Determine the IPs to use for SNAT
	var lbIPv4 net.IP
	var lbIPv6 net.IP
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			ip := net.ParseIP(ingress.IP)
			if ip.To4() != nil && lbIPv4 == nil {
				lbIPv4 = ip
			} else if ip.To16() != nil && lbIPv6 == nil {
				lbIPv6 = ip
			}
			if lbIPv4 != nil && lbIPv6 != nil {
				break // Both IPs found, no need to continue
			}
		}
	}

	// Get gateway node name
	gwNodeName := ""
	if len(sl2s.Items) > 0 {
		gwNodeName = sl2s.Items[0].Status.Node
	}

	// Filter for endpoints on this node and get their src ips to use for SNAT
	var srcIPv4s, srcIPv6s []net.IP
	for _, slice := range slices.Items {
		for _, ep := range slice.Endpoints {
			// If filtering for node, skip endpoints not on this node
			// But always include all endpoints, if this is a gateway node, because traffic is
			// identified by the pods src ip.
			if gwNodeName != c.nodeName && c.filterForNode && (ep.NodeName == nil || *ep.NodeName != c.nodeName) {
				continue
			}
			for _, address := range ep.Addresses {
				ip := net.ParseIP(address)
				if ip.To4() != nil && slice.AddressType == discoveryv1.AddressTypeIPv4 {
					srcIPv4s = append(srcIPv4s, ip)
				} else if ip.To16() != nil && slice.AddressType == discoveryv1.AddressTypeIPv6 {
					srcIPv6s = append(srcIPv6s, ip)
				}
			}
		}
	}

	if len(srcIPv4s) == 0 && len(srcIPv6s) == 0 {
		err := c.es.DeleteEgressRule(req.NamespacedName.String())
		if err != nil {
			logger.Error(err, "Failed to delete egress rule from egress service")
			return ctrl.Result{}, err
		}
		if c.filterForNode {
			logger.Info("Service reconciled successfully", "state", "absent", "reason", "no endpoints on this node")
		} else {
			logger.Info("Service reconciled successfully", "state", "absent", "reason", "no endpoints found")
		}
		return ctrl.Result{}, nil
	}

	if err := c.es.UpdateEgressRule(req.NamespacedName.String(), lbIPv4, lbIPv6, srcIPv4s, srcIPv6s, gwNodeName); err != nil {
		logger.Error(err, "Failed to update egress rule on egress service")
		return ctrl.Result{}, err
	}
	logger.Info("Service reconciled successfully", "state", "present", "lbIPv4", lbIPv4, "lbIPv6", lbIPv6, "srcIPv4s", srcIPv4s, "srcIPv6s", srcIPv6s, "gwNodeName", gwNodeName)
	return ctrl.Result{}, nil
}
