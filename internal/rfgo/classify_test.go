package rfgo

import (
	"testing"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

func TestClassifyBluetooth_NotifyStream(t *testing.T) {
	got := ClassifyBluetooth(proto.BluetoothData{
		Address:  "AA:BB:CC:DD:EE:FF",
		Notifies: []string{"01ff00aabb", "02ff00ccdd"},
	})
	if len(got) != 1 || got[0].Severity != "info" {
		t.Fatalf("want 1 info, got %+v", got)
	}
}

func TestClassifyBluetooth_GATTRead(t *testing.T) {
	got := ClassifyBluetooth(proto.BluetoothData{
		Address: "AA:BB:CC:DD:EE:FF",
		GATTHex: "deadbeefcafe",
	})
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("want 1 medium, got %+v", got)
	}
}

func TestClassifyBluetooth_GATTWritable(t *testing.T) {
	got := ClassifyBluetooth(proto.BluetoothData{
		Address: "AA:BB:CC:DD:EE:FF",
		Chars: []string{
			"00001800-0000-1000-8000-00805f9b34fb|0x0002|00002a00-0000-1000-8000-00805f9b34fb|read",
			"00001800-0000-1000-8000-00805f9b34fb|0x0004|00002a01-0000-1000-8000-00805f9b34fb|write,write-without-response",
		},
	})
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("want 1 medium, got %+v", got)
	}
}

func TestClassifyBluetooth_ScanIsNotVuln(t *testing.T) {
	if got := ClassifyBluetooth(proto.BluetoothData{
		Address: "AA:BB:CC:DD:EE:FF",
		Name:    "Speaker",
		RSSI:    -60,
	}); len(got) != 0 {
		t.Fatalf("scan should not produce vuln, got %+v", got)
	}
}

func TestClassifyBluetooth_AdvertisementIsNotVuln(t *testing.T) {
	if got := ClassifyBluetooth(proto.BluetoothData{
		Address:    "AA:BB:CC:DD:EE:FF",
		AdvName:    "Beacon",
		SvcUUIDs16: []string{"fe9f"},
		MfgName:    "TestCorp",
	}); len(got) != 0 {
		t.Fatalf("advertisement should not produce vuln, got %+v", got)
	}
}

func TestClassifyBluetooth_ErrorSkipped(t *testing.T) {
	if got := ClassifyBluetooth(proto.BluetoothData{
		Address: "AA:BB:CC:DD:EE:FF",
		Error:   "connection refused",
	}); len(got) != 0 {
		t.Fatalf("error should skip, got %+v", got)
	}
}

func TestClassifyBluetooth_DoneSkipped(t *testing.T) {
	if got := ClassifyBluetooth(proto.BluetoothData{
		Done:    true,
		Address: "AA:BB:CC:DD:EE:FF",
		GATTHex: "01",
	}); len(got) != 0 {
		t.Fatalf("done should skip, got %+v", got)
	}
}
