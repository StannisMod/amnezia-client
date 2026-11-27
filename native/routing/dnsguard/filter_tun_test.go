package dnsguard

import (
	"bytes"
	"io"
	"testing"
	"time"
)

type filterBatchTUN struct {
	*nativeTestTUN
	batch [][]byte
	err   error
}

func (b *filterBatchTUN) Read(data [][]byte, sizes []int, offset int) (int, error) {
	if b.batch == nil {
		return 0, io.EOF
	}
	batch := b.batch
	b.batch = nil
	for i, packet := range batch {
		sizes[i] = copy(data[i][offset:], packet)
	}
	return len(batch), b.err
}

func TestFilterTUNPreservesNativeBatchOrderBytesAndHeadroom(t *testing.T) {
	for _, ending := range []error{nil, io.EOF} {
		base := &filterBatchTUN{nativeTestTUN: newNativeTestTUN(),
			batch: [][]byte{{0x60, 1}, {0x45, 0x77}, {0x45, 1, 2, 3}, {0x45, 2, 4, 5}}, err: ending}
		wrapped := WrapPacketFilter(base, func(packet []byte) bool {
			return packet[0]>>4 == 6 || packet[1] == 0x77
		})
		buffers := make([][]byte, 4)
		for i := range buffers {
			buffers[i] = bytes.Repeat([]byte{byte(0xa0 + i)}, 256)
		}
		sizes := make([]int, 4)
		n, err := wrapped.Read(buffers, sizes, 16)
		if n != 2 || err != ending {
			t.Fatal("native batch or read error changed", n, err)
		}
		for i, expected := range [][]byte{{0x45, 1, 2, 3}, {0x45, 2, 4, 5}} {
			if !bytes.Equal(buffers[i][16:16+sizes[i]], expected) ||
				!bytes.Equal(buffers[i][:16], bytes.Repeat([]byte{byte(0xa0 + i)}, 16)) {
				t.Fatal("native bytes, batch order or headroom changed")
			}
		}
		if _, err := wrapped.Write([][]byte{buffers[0][:16+sizes[0]]}, 16); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(<-base.toOS, []byte{0x45, 1, 2, 3}) {
			t.Fatal("native inbound write was intercepted or changed")
		}
		wrapped.Close()
	}
}

func TestFilterTUNAllConsumedContinuesSoleReaderAndStop(t *testing.T) {
	base := newNativeTestTUN()
	wrapped := WrapPacketFilter(base, func(packet []byte) bool { return packet[0]>>4 == 6 })
	base.fromOS <- []byte{0x60, 1}
	base.fromOS <- []byte{0x45, 2}
	buffers, sizes := [][]byte{make([]byte, 256)}, make([]int, 1)
	n, err := wrapped.Read(buffers, sizes, 8)
	if err != nil || n != 1 || !bytes.Equal(buffers[0][8:8+sizes[0]], []byte{0x45, 2}) {
		t.Fatal("all-filtered batch lost the next native packet", n, err)
	}
	done := make(chan error, 1)
	go func() { _, err := wrapped.Read(buffers, sizes, 8); done <- err }()
	wrapped.Close()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatal("native close not propagated", err)
		}
	case <-time.After(time.Second):
		t.Fatal("native reader survived Stop")
	}
}
