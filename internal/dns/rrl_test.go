package dns

import (
	"testing"

	"smartdns/internal/config"
)

func TestRRLTokenBucket(t *testing.T) {
	s := &Server{cfg: config.Config{DNSRRLEnabled: true, DNSRRLRate: 2}, rrl: map[string]*tokenBucket{}}
	if !s.allowIP("1.1.1.1") || !s.allowIP("1.1.1.1") {
		t.Fatal("expected initial tokens")
	}
	if s.allowIP("1.1.1.1") {
		t.Fatal("expected rate limit")
	}
}
