# MetalEG
MetalEG is an egress controller for Kubernetes Services, which allows a [MetalLB](https://metallb.io) IP address to be used as source IP for Pods. Only Layer 2 mode is supported. It configures firewall and routing rules on each cluster node to forward the traffic to the node, which holds the desired MetalLB IP address, then it performs SNAT to rewrite the src ip of the pod.

![Traffic forwarding](artifacts/traffic.svg)

## Prerequisites
- Kubernetes cluster with MetalLB installed and configured in Layer 2 mode
- Cluster nodes must be on same ethernet (no NAT between nodes)

## Installation
You can use the Kustomization in this repository to deploy MetalEG in your cluster. By default the namespace `metallb-system`, the firewall backend `iptables` and route backend `netlink` will be used. By default all private IPv4 and IPv6 ranges will be excluded from rerouting and masquerading (which should include your cluster and service ip range).
```sh
kubectl apply -k https://github.com/gerolf-vent/metaleg/k8s
```

## Configuration
The controller is configured via environment variables:

| Name | Default | Description |
| ---- | ------- | ----------- |
| NODE_NAME | - | Hostname of the K8s node the agent is running on |
| METALLB_NAMESPACE | `metallb-system` | Namespace where MetalLB is running in |
| FILTER_ENDPOINTS_FOR_NODE | `true` | Whether to only redirect traffic from pod ips on the same node or all pod ips. |
| FIREWALL_BACKEND | `iptables` | Firewall backend to use for SNAT rules and marking packages |
| FIREWALL_MASK | `0x00F00000` | Firewall mask to use for marking packages (must be continous) |
| FIREWALL_EXCLUDE_DST_CIDRS | `10.0.0.0/8, 176.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fc00::/7, fe80::/10` | Comma separated list of CIDRs to exclude from rerouting and masquerading (e.g. cluster pod/service CIDRs) |
| ROUTE_BACKEND | `netlink` | Route backend to use for rerouting traffic to specific nodes |
| ROUTE_TABLE_ID_OFFSET | `100000` | Starting point to allocate routing table ids |
| RECONCILIATION_INTERVAL | `5m` | Time interval for full reconciliation and garbage collection |
| METRICS_BIND_ADDRESS | `:21793` | Bind address for Prometheus metrics (use `0` to disable) |
| HEALTH_PROBE_BIND_ADDRESS | `:21794` | Bind address for Health probes (use `0` to disable) |

> [!NOTE]
> `FIREWALL_EXCLUDE_DST_CIDRS` must include your cluster pod and service CIDRs to avoid breaking internal cluster communication.

### Firewall backends
| Name | Description |
| ---- | ----------- |
| `iptables` | Modern iptables backend that chooses `nf_tables` or legacy `ip_tables` under the hood automatically |

### Route backends
| Name | Description |
| ---- | ----------- |
| `netlink` | Standart linux network stack |

## Usage
After deploying MetalEG to your cluster, just add the label `metaleg.de/rewriteSrcIP: "true"` to any Service, that's configured with an MetalLB IP in Layer2 mode.
```yaml
apiVersion: v1
kind: Service
metadata:
  name: metaleg-test
  labels:
    metaleg.de/rewriteSrcIP: "true"
  annotations:
    metallb.io/loadBalancerIPs: "1.2.3.4,1111:2222:3333:4444::1"
spec:
  selector:
    app: metaleg-test
  ipFamilyPolicy: PreferDualStack
  ports:
  - name: dummy
    port: 1234
    targetPort: 1234
  type: LoadBalancer
```

## Compatibility
Because this controller currently uses firewall marks and routes on the standart linux network stack, it should work with a wide range of CNIs. All of the cluster nodes, where MetalEG is running on, must be connected directly (because forwarding happens by rewriting the nexthop of packages).
| CNI | Status | Notes |
| --- | ------ | ----- |
| [kube-router](https://kube-router.io) | Tested and supported | `iptables` firewall backend and `netlink` route backend recommended |
| [Cilium](https://cilium.io) | Not working |

## Testing
For running all Go tests, you can use the `docker-compose.yaml` provided. It will start a container with all dependencies installed and the `NET_ADMIN` capability enabled (required for iptables/ipset tests). You can start the tests with `docker compose run --rm go-test` or `podman-compose up`.
