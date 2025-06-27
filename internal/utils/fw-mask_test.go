package utils

import (
	"testing"
)

func TestParseFWMask(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FWMask
		wantErr bool
	}{
		{"valid continuous mask", "0xFF00", FWMask(0xFF00), false},
		{"valid single bit", "0x1", FWMask(0x1), false},
		{"valid all bits", "0xFFFFFFFF", FWMask(0xFFFFFFFF), false},
		{"valid continuous lower bits", "0x7", FWMask(0x7), false},
		{"missing 0x prefix", "FF00", 0, true},
		{"too long", "0x1FFFFFFFF", 0, true},
		{"invalid hex", "0xGG", 0, true},
		{"empty string", "", 0, true},
		{"discontinuous mask", "0xF0F", 0, true},
		{"zero mask", "0x0", FWMask(0x0), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFWMask(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFWMask() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseFWMask() = 0x%X, want 0x%X", got, tt.want)
			}
		})
	}
}

func TestFWMask_IsContinuous(t *testing.T) {
	tests := []struct {
		name string
		mask FWMask
		want bool
	}{
		{"zero mask", FWMask(0x0), true},
		{"single bit", FWMask(0x1), true},
		{"continuous lower bits", FWMask(0x7), true},
		{"continuous middle bits", FWMask(0x78), true},
		{"continuous upper bits", FWMask(0xF000), true},
		{"all bits", FWMask(0xFFFFFFFF), true},
		{"discontinuous", FWMask(0x101), false},
		{"alternating bits", FWMask(0x55555555), false},
		{"gap in middle", FWMask(0xF0F), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mask.IsContinous(); got != tt.want {
				t.Errorf("FWMask.IsContinuous() = %v, want %v for mask 0x%X", got, tt.want, tt.mask)
			}
		})
	}
}

func TestFWMask_Size(t *testing.T) {
	tests := []struct {
		name string
		mask FWMask
		want uint
	}{
		{"zero mask", FWMask(0x0), 0},
		{"single bit", FWMask(0x1), 2},
		{"two bits", FWMask(0x3), 4},
		{"three bits", FWMask(0x7), 8},
		{"four bits", FWMask(0xF), 16},
		{"eight bits", FWMask(0xFF), 256},
		{"shifted mask", FWMask(0xF0), 16},
		{"16 bits", FWMask(0xFFFF), 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mask.Size(); got != tt.want {
				t.Errorf("FWMask.Size() = %v, want %v for mask 0x%X", got, tt.want, tt.mask)
			}
		})
	}
}

func TestFWMask_Shift(t *testing.T) {
	tests := []struct {
		name string
		mask FWMask
		want uint
	}{
		{"zero mask", FWMask(0x0), 0},
		{"no shift", FWMask(0x1), 0},
		{"shift by 1", FWMask(0x2), 1},
		{"shift by 4", FWMask(0x10), 4},
		{"shift by 8", FWMask(0x100), 8},
		{"continuous mask shifted", FWMask(0xF0), 4},
		{"high bit", FWMask(0x80000000), 31},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mask.Shift(); got != tt.want {
				t.Errorf("FWMask.Shift() = %v, want %v for mask 0x%X", got, tt.want, tt.mask)
			}
		})
	}
}

func TestFWMask_Offset(t *testing.T) {
	tests := []struct {
		name string
		mask FWMask
		want uint
	}{
		{"zero mask", FWMask(0x0), 0},
		{"no offset", FWMask(0x1), 0},
		{"offset by 2", FWMask(0x2), 2},
		{"offset by 16", FWMask(0x10), 16},
		{"offset by 256", FWMask(0x100), 256},
		{"continuous mask with offset", FWMask(0xF0), 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mask.Offset(); got != tt.want {
				t.Errorf("FWMask.Offset() = %v, want %v for mask 0x%X", got, tt.want, tt.mask)
			}
		})
	}
}

func TestFWMask_Integration(t *testing.T) {
	// Test that parsing and then using the mask works correctly
	maskStr := "0xFF00"
	mask, err := ParseFWMask(maskStr)
	if err != nil {
		t.Fatalf("ParseFWMask(%s) failed: %v", maskStr, err)
	}

	if !mask.IsContinous() {
		t.Errorf("Mask 0x%X should be continuous", mask)
	}

	expectedSize := uint(256)
	if size := mask.Size(); size != expectedSize {
		t.Errorf("Size() = %v, want %v", size, expectedSize)
	}

	expectedShift := uint(8)
	if shift := mask.Shift(); shift != expectedShift {
		t.Errorf("Shift() = %v, want %v", shift, expectedShift)
	}

	expectedOffset := uint(256)
	if offset := mask.Offset(); offset != expectedOffset {
		t.Errorf("Offset() = %v, want %v", offset, expectedOffset)
	}
}
