package firewall_manager

import (
	"net"

	"github.com/gerolf-vent/metaleg/internal/utils/ipset"
	"github.com/gerolf-vent/metaleg/internal/utils/state"
)

type IPSetIPsSynchronizer struct {
	SetName string
	Entries []net.IP

	ips ipset.IPSet
}

func NewIPSetIPsSynchronizer(ips ipset.IPSet) *IPSetIPsSynchronizer {
	return &IPSetIPsSynchronizer{
		ips: ips,
	}
}

func (s *IPSetIPsSynchronizer) Sync() error {
	stateSynchronizer := &state.StateSynchronizer[net.IP, net.IP]{
		Get: func() ([]net.IP, error) {
			return s.ips.ListEntries(s.SetName)
		},
		Prepare: func(entry net.IP) (net.IP, net.IP) {
			return entry, entry
		},
		Filter: func(entry net.IP, _ net.IP) bool {
			return true
		},
		Equal: func(existingEntry net.IP, _ net.IP, entry net.IP) bool {
			return existingEntry.Equal(entry)
		},
		Add: func(entry net.IP) error {
			_, err := s.ips.EnsureEntry(s.SetName, entry)
			return err
		},
		Delete: func(entry net.IP) error {
			_, err := s.ips.DeleteEntry(s.SetName, entry)
			return err
		},
	}

	return stateSynchronizer.SyncSet(s.Entries)
}
