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
