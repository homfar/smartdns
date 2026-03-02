package validate

import "testing"

func TestAData(t *testing.T) {
	if err := AData(`{"mode":"SINGLE","ip":"1.2.3.4"}`); err != nil {
		t.Fatal(err)
	}
	if err := AData(`{"mode":"GEO","iran_ip":"1.1.1.1","foreign_ip":"2.2.2.2"}`); err != nil {
		t.Fatal(err)
	}
	if err := AData(`{"mode":"GEO","iran_ip":"x","foreign_ip":"2.2.2.2"}`); err == nil {
		t.Fatal("expected error")
	}
}
