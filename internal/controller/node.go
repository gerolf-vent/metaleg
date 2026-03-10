package controller

import (
	"context"
	"net"

	"github.com/gerolf-vent/metaleg/internal/core"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type nodeController struct {
	client     client.Client
	reconciler Reconciler
}

func AttachNodeController(mgr ctrl.Manager, reconciler Reconciler) error {
	c := &nodeController{
		client:     mgr.GetClient(),
		reconciler: reconciler,
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

	// Determine the Node's IP addresses
	var nodeIPv4, nodeIPv6 net.IP
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			if ip := net.ParseIP(addr.Address); ip != nil {
				if ip.To4() != nil {
					if nodeIPv4 == nil {
						nodeIPv4 = ip
					}
				} else {
					if nodeIPv6 == nil {
						nodeIPv6 = ip
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
