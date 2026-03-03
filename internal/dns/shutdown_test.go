package dns

import (
	"context"
	"testing"
	"time"
)

func TestGracefulShutdownNoServers(t *testing.T) {
	s := &Server{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
