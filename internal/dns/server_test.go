package dns

import "testing"

func TestLongestZone(t *testing.T) {
	zones := []string{"example.com", "sub.example.com"}
	if got := LongestZone("a.sub.example.com.", zones); got != "sub.example.com" {
		t.Fatal(got)
	}
}
