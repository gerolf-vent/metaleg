package route_manager

type RouteManager interface {
	Setup() error
	ReconcileNodeRoute(route *NodeRoute, present bool) error
	CleanupNodeRoutes(routes map[string]*NodeRoute) error
}
