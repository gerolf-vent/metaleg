package mock

import (
	"net"
	"slices"

	"github.com/gerolf-vent/metaleg/internal/utils/ipset"
)

type IPSet struct {
	Sets           map[string]bool        // setName -> exists
	Entries        map[string][]net.IP    // setName -> IPs
	NetworkSets    map[string]bool        // setName -> exists
	NetworkEntries map[string][]net.IPNet // setName -> CIDRs
}

func NewIPSet() *IPSet {
	return &IPSet{
		Sets:           make(map[string]bool),
		Entries:        make(map[string][]net.IP),
		NetworkSets:    make(map[string]bool),
		NetworkEntries: make(map[string][]net.IPNet),
	}
}

func (s *IPSet) ListSets() ([]string, error) {
	var names []string
	for name := range s.Sets {
		names = append(names, name)
	}
	for name := range s.NetworkSets {
		names = append(names, name)
	}
	return names, nil
}

func (s *IPSet) SetExists(name string) (bool, error) {
	return s.Sets[name], nil
}

func (s *IPSet) EnsureSet(name string, proto ipset.Protocol) (bool, error) {
	created := !s.Sets[name]
	s.Sets[name] = true
	if _, ok := s.Entries[name]; !ok {
		s.Entries[name] = nil
	}
	return created, nil
}

func (s *IPSet) DeleteSet(name string) (bool, error) {
	if s.Sets[name] {
		delete(s.Sets, name)
		delete(s.Entries, name)
		return true, nil
	}
	if s.NetworkSets[name] {
		delete(s.NetworkSets, name)
		delete(s.NetworkEntries, name)
		return true, nil
	}
	return false, nil
}

func (s *IPSet) ListEntries(setName string) ([]net.IP, error) {
	return s.Entries[setName], nil
}

func (s *IPSet) EntryExists(setName string, entry net.IP) (bool, error) {
	for _, ip := range s.Entries[setName] {
		if ip.Equal(entry) {
			return true, nil
		}
	}
	return false, nil
}

func (s *IPSet) EnsureEntry(setName string, entry net.IP) (bool, error) {
	for _, ip := range s.Entries[setName] {
		if ip.Equal(entry) {
			return false, nil
		}
	}
	s.Entries[setName] = append(s.Entries[setName], entry)
	return true, nil
}

func (s *IPSet) DeleteEntry(setName string, entry net.IP) (bool, error) {
	for i, ip := range s.Entries[setName] {
		if ip.Equal(entry) {
			s.Entries[setName] = slices.Delete(s.Entries[setName], i, i+1)
			return true, nil
		}
	}
	return false, nil
}

func (s *IPSet) NetworkSetExists(name string) (bool, error) {
	return s.NetworkSets[name], nil
}

func (s *IPSet) EnsureNetworkSet(name string, proto ipset.Protocol) (bool, error) {
	created := !s.NetworkSets[name]
	s.NetworkSets[name] = true
	if _, ok := s.NetworkEntries[name]; !ok {
		s.NetworkEntries[name] = nil
	}
	return created, nil
}

func (s *IPSet) DeleteNetworkSet(name string) (bool, error) {
	if !s.NetworkSets[name] {
		return false, nil
	}
	delete(s.NetworkSets, name)
	delete(s.NetworkEntries, name)
	return true, nil
}

func (s *IPSet) NetworkEntryExists(name string, cidr net.IPNet) (bool, error) {
	for _, c := range s.NetworkEntries[name] {
		if c.IP.Equal(cidr.IP) && c.Mask.String() == cidr.Mask.String() {
			return true, nil
		}
	}
	return false, nil
}

func (s *IPSet) ListNetworkEntries(setName string) ([]net.IPNet, error) {
	return s.NetworkEntries[setName], nil
}

func (s *IPSet) EnsureNetworkEntry(setName string, cidr *net.IPNet) (bool, error) {
	for _, c := range s.NetworkEntries[setName] {
		if c.IP.Equal(cidr.IP) && c.Mask.String() == cidr.Mask.String() {
			return false, nil
		}
	}
	s.NetworkEntries[setName] = append(s.NetworkEntries[setName], *cidr)
	return true, nil
}

func (s *IPSet) DeleteNetworkEntry(setName string, cidr *net.IPNet) (bool, error) {
	for i, c := range s.NetworkEntries[setName] {
		if c.IP.Equal(cidr.IP) && c.Mask.String() == cidr.Mask.String() {
			s.NetworkEntries[setName] = slices.Delete(s.NetworkEntries[setName], i, i+1)
			return true, nil
		}
	}
	return false, nil
}
