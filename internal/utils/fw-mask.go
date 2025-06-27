package utils

import (
	"errors"
	"fmt"
)

type FWMask uint32

func ParseFWMask(mask string) (FWMask, error) {
	var fwMask FWMask
	if len(mask) < 2 || mask[0:2] != "0x" {
		return 0, errors.New("FWMask must start with '0x'")
	}
	if len(mask) > 10 {
		return 0, errors.New("FWMask must be a 8-byte hexadecimal number")
	}
	len, err := fmt.Sscanf(mask, "0x%x", &fwMask)
	if err != nil || len < 1 {
		return 0, errors.New("FWMask must be a valid hexadecimal number")
	}
	if !fwMask.IsContinous() {
		return 0, errors.New("FWMask must be continuous, i.e. have one contiguous block of 1 bits")
	}
	return fwMask, nil
}

func (m FWMask) IsContinous() bool {
	mask := uint32(m)

	// Skip trailing zero bits.
	for mask != 0 && mask&1 == 0 {
		mask >>= 1
	}
	// Skip contiguous 1 bits.
	for mask != 0 && mask&1 == 1 {
		mask >>= 1
	}
	// If any bits remain, it's not continuous.
	return mask == 0
}

func (m FWMask) Size() uint {
	mask := uint32(m)
	size := uint(0)

	// Calculate the size of the mask.
	for mask != 0 {
		if mask&1 == 1 {
			if size == 0 {
				size = 2
			} else {
				size *= 2
			}
		}
		mask >>= 1
	}

	return size
}

func (m FWMask) Shift() uint {
	mask := uint32(m)
	shift := uint(0)

	// Calculate the shift of the first set bit.
	for mask != 0 && mask&1 == 0 {
		mask >>= 1
		shift++
	}

	return shift
}

func (m FWMask) Offset() uint {
	mask := uint32(m)
	offset := uint(0)

	// Calculate the offset of the first set bit.
	for mask != 0 && mask&1 == 0 {
		mask >>= 1
		if offset == 0 {
			offset = 2
		} else {
			offset *= 2
		}
	}

	return offset
}
