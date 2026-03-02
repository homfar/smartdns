package geo

import "testing"

func TestSelectA(t *testing.T) {
	if got := SelectA("IR", "1.1.1.1", "2.2.2.2"); got != "1.1.1.1" {
		t.Fatal(got)
	}
	if got := SelectA("US", "1.1.1.1", "2.2.2.2"); got != "2.2.2.2" {
		t.Fatal(got)
	}
}
