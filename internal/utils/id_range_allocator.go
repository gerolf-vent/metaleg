package utils

import (
	"errors"

	"github.com/bits-and-blooms/bitset"
)

var (
	ErrPoolExhausted = errors.New("ID pool exhausted")
)

type IDRangeAllocator struct {
	bitset *bitset.BitSet
}

func NewIDRangeAllocator(size uint) *IDRangeAllocator {
	return &IDRangeAllocator{
		bitset: bitset.New(size),
	}
}

func (a *IDRangeAllocator) Allocate() (uint, error) {
	for i := uint(0); i < a.bitset.Len(); i++ {
		if !a.bitset.Test(i) {
			a.bitset.Set(i)
			return i, nil
		}
	}
	return 0, ErrPoolExhausted
}

func (a *IDRangeAllocator) Release(id uint) {
	if id >= a.bitset.Len() {
		return // Ignore out-of-range IDs
	}
	a.bitset.Clear(id)
}

func (a *IDRangeAllocator) IsAllocated(id uint) bool {
	if id >= a.bitset.Len() {
		return false // Out-of-range IDs are considered not allocated
	}
	return a.bitset.Test(id)
}

func (a *IDRangeAllocator) Size() uint {
	return a.bitset.Len()
}

func (a *IDRangeAllocator) AllocatedCount() uint {
	return uint(a.bitset.Count())
}

func (a *IDRangeAllocator) FreeCount() uint {
	return a.Size() - a.AllocatedCount()
}
