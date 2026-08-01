package strictdecode

import "testing"

type decodeFixture struct {
	Count int `json:"count"`
}

func TestDecodeStrictlyMapsAndRejectsUnknownKeys(t *testing.T) {
	var output decodeFixture
	if err := Decode(map[string]any{"count": "7"}, &output); err != nil {
		t.Fatal(err)
	}
	if output.Count != 7 {
		t.Fatalf("weak scalar conversion failed: %+v", output)
	}
	if err := Decode(map[string]any{"coutn": 7}, &output); err == nil {
		t.Fatal("unknown key should fail")
	}
}
