package firewall_manager

import (
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

// Helper function to check if two port strings contain the same ports (order independent)
func containsSamePorts(actual, expected string) bool {
	actualPorts := set.New[string]()
	expectedPorts := set.New[string]()

	for _, port := range strings.Split(actual, ",") {
		actualPorts.Add(strings.TrimSpace(port))
	}
	for _, port := range strings.Split(expected, ",") {
		expectedPorts.Add(strings.TrimSpace(port))
	}

	return actualPorts.Equals(expectedPorts)
}
