package metaleg

import (
	"context"
	"net"

	es "github.com/gerolf-vent/metaleg/internal/egress-service"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type nodeController struct {
	client client.Client
	es     *es.EgressService
}

func AttachNodeController(mgr ctrl.Manager, es *es.EgressService) error {
	c := &nodeController{
		client: mgr.GetClient(),
		es:     es,
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
	logger.Info("Reconciling Node")

	// Fetch the Node object
	node := &corev1.Node{}
	if err := c.client.Get(ctx, req.NamespacedName, node); err != nil {
		if apierrors.IsNotFound(err) {
			err2 := c.es.DeleteNodeRoute(req.Name)
			if err2 != nil {
				logger.Error(err2, "Failed to delete Node from egress service")
				return ctrl.Result{}, err2
			}
			logger.Info("Node reconciled successfully", "state", "absent")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Node from K8s API")
		return ctrl.Result{}, err
	}

	var nodeIPv4, nodeIPv6 net.IP
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			if ip := net.ParseIP(addr.Address); ip != nil {
				if ip.To4() != nil && nodeIPv4 == nil {
					nodeIPv4 = ip
				} else if ip.To16() != nil && nodeIPv6 == nil {
					nodeIPv6 = ip
				}
			}
		}
		if nodeIPv4 != nil && nodeIPv6 != nil {
			break // Both IPs found, no need to continue
		}
	}

	err := c.es.UpdateNodeRoute(req.Name, nodeIPv4, nodeIPv6)
	if err != nil {
		logger.Error(err, "Failed to update Node on egress service")
		return ctrl.Result{}, err
	}
	logger.Info("Node reconciled successfully", "state", "present", "nodeIPv4", nodeIPv4, "nodeIPv6", nodeIPv6)
	return ctrl.Result{}, nil
}
