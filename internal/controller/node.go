package controller

import (
	"context"
	"net"
	"slices"

	"github.com/gerolf-vent/metaleg/internal/core"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type nodeController struct {
	client       client.Client
	reconciler   Reconciler
	nodeAddrType NodeAddressType
}

func AttachNodeController(mgr ctrl.Manager, reconciler Reconciler, nodeAddrType NodeAddressType) error {
	c := &nodeController{
		client:       mgr.GetClient(),
		reconciler:   reconciler,
		nodeAddrType: nodeAddrType,
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Complete(c); err != nil {
		return err
	}

	return nil
}

func (c *nodeController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.LoggerFrom(ctx)
	logger.V(1).Info("Reconciling Node")

	// Fetch the Node object
	node := &corev1.Node{}
	if err := c.client.Get(ctx, req.NamespacedName, node); err != nil {
		if apierrors.IsNotFound(err) {
			err2 := c.reconciler.DeleteNode(req.Name)
			if err2 != nil {
				logger.Error(err2, "Failed to reconcile deleted Node")
				return ctrl.Result{}, err2
			}
			logger.Info("Successfully reconciled Node", "state", "absent", "reason", "object not found")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Node from K8s API")
		return ctrl.Result{}, err
	}

	// Determine the desired NodeAddressType based on the configuration
	var desiredAddrTypes []corev1.NodeAddressType
	switch c.nodeAddrType {
	case NodeAddressTypeInternal:
		desiredAddrTypes = append(desiredAddrTypes, corev1.NodeInternalIP)
	case NodeAddressTypeExternal:
		desiredAddrTypes = append(desiredAddrTypes, corev1.NodeExternalIP)
	case NodeAddressTypeAny:
		desiredAddrTypes = append(desiredAddrTypes, corev1.NodeInternalIP, corev1.NodeExternalIP)
	}

	// Determine the Node's IP addresses
	var nodeIPv4, nodeIPv6 net.IP
	var nodeIPv4AddrType, nodeIPv6AddrType corev1.NodeAddressType
	for _, addr := range node.Status.Addresses {
		if slices.Contains(desiredAddrTypes, addr.Type) {
			if ip := net.ParseIP(addr.Address); ip != nil {
				if ip.To4() != nil {
					if nodeIPv4 == nil || nodeIPv4AddrType != corev1.NodeInternalIP {
						nodeIPv4 = ip
						nodeIPv4AddrType = addr.Type
					}
				} else {
					if nodeIPv6 == nil || nodeIPv6AddrType != corev1.NodeInternalIP {
						nodeIPv6 = ip
						nodeIPv6AddrType = addr.Type
					}
				}
			}
		}
		if nodeIPv4 != nil && nodeIPv6 != nil {
			break // Both IPs found, no need to continue
		}
	}

	egressNode := core.Node{
		Name: node.Name,
		IPv4: nodeIPv4,
		IPv6: nodeIPv6,
	}

	err := c.reconciler.UpdateNode(egressNode)
	if err != nil {
		logger.Error(err, "Failed to reconcile updated Node")
		return ctrl.Result{}, err
	}
	logger.Info("Successfully reconciled Node", "state", "present", "nodeIPv4", egressNode.IPv4, "nodeIPv6", egressNode.IPv6)
	return ctrl.Result{}, nil
}
