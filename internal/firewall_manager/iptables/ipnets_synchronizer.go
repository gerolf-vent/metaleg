package iptables

import (
	"net"

	"github.com/gerolf-vent/metaleg/internal/utils/ipset"
	"github.com/gerolf-vent/metaleg/internal/utils/state"
)

type IPSetIPNetsSynchronizer struct {
	SetName string
	Entries []net.IPNet

	ips ipset.IPSet
}

func NewIPSetIPNetsSynchronizer(ips ipset.IPSet) *IPSetIPNetsSynchronizer {
	return &IPSetIPNetsSynchronizer{
		ips: ips,
	}
}

func (s *IPSetIPNetsSynchronizer) Sync() error {
	stateSynchronizer := &state.StateSynchronizer[net.IPNet, net.IPNet]{
		Get: func() ([]net.IPNet, error) {
			return s.ips.ListNetworkEntries(s.SetName)
		},
		Prepare: func(entry net.IPNet) (net.IPNet, net.IPNet) {
			return entry, entry
		},
		Filter: func(entry net.IPNet, _ net.IPNet) bool {
			return true
		},
		Equal: func(existingEntry net.IPNet, _ net.IPNet, entry net.IPNet) bool {
			return existingEntry.String() == entry.String()
		},
		Add: func(entry net.IPNet) error {
			_, err := s.ips.EnsureNetworkEntry(s.SetName, &entry)
			return err
		},
		Delete: func(entry net.IPNet) error {
			_, err := s.ips.DeleteNetworkEntry(s.SetName, &entry)
			return err
		},
	}

	return stateSynchronizer.SyncSet(s.Entries)
}
