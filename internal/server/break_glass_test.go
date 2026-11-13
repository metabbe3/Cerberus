package server

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBreakGlass_NoDeadlock(t *testing.T) {
	bg := newBreakGlassManager()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: Status loop (reader)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = bg.Status("key-1")
			}
		}
	}()

	// Goroutine 2: Activate loop (writer)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				bg.Activate("key-1", 10*time.Millisecond, "test reason")
				time.Sleep(100 * time.Microsecond)
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded without deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: goroutines did not finish within timeout")
	}
}
