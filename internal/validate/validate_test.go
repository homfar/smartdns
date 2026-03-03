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

func TestAAAAData(t *testing.T) {
	if err := AAAAData(`{"ip":"2001:db8::1"}`); err != nil {
		t.Fatal(err)
	}
	if err := AAAAData(`{"ip":"1.2.3.4"}`); err == nil {
		t.Fatal("expected ipv6 validation error")
	}
}
