package dns

import (
	"testing"

	"smartdns/internal/validate"
)

func FuzzFQDNNormalize(f *testing.F) {
	f.Add("Example.COM.")
	f.Add("*.example.com")
	f.Fuzz(func(t *testing.T, in string) {
		n := validate.NormalizeDomain(in)
		_ = validate.FQDN(n)
	})
}
