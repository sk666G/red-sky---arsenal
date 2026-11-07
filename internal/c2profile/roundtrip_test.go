package c2profile

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFullFrameRoundtrip(t *testing.T) {
	cases := []struct {
		enc     string
		padMin  int
		padMax  int
	}{
		{"none", 0, 0},
		{"base64", 0, 0},
		{"hex", 0, 0},
		{"none", 16, 64},
		{"base64", 16, 64},
		{"hex", 16, 64},
	}
	for _, c := range cases {
		p := &Profile{BodyEncoding: c.enc, PaddingMin: c.padMin, PaddingMax: c.padMax}
		// build envelope-like payload
		payload, _ := json.Marshal(map[string]string{"cmd": "whoami", "id": "agent-1"})
		envelope, _ := json.Marshal(map[string]json.RawMessage{"payload": payload, "type": json.RawMessage(`"task"`)})
		raw := envelope

		// sender: encode + pad
		enc, err := p.EncodeBody(raw)
		if err != nil {
			t.Fatalf("%s encode: %v", c.enc, err)
		}
		wire := p.PadBody(enc)

		// receiver: strip + decode
		stripped := StripPadding(wire)
		dec, err := p.DecodeBody(stripped)
		if err != nil {
			t.Fatalf("%s decode: %v", c.enc, err)
		}
		if !bytes.Equal(dec, raw) {
			t.Fatalf("%s/pad%d-%d: roundtrip mismatch\ngot: %s\nwant: %s", c.enc, c.padMin, c.padMax, dec, raw)
		}
	}
}
