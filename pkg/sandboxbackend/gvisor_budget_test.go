// SPDX-License-Identifier: AGPL-3.0-only

package sandboxbackend

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// heldFor returns a channel that closes after d, for holding a fake start.
func heldFor(d time.Duration) <-chan struct{} {
	done := make(chan struct{})
	time.AfterFunc(d, func() { close(done) })
	return done
}

// The registry controls how long a pull takes, so the pull runs under its
// own deadline (the budget minus the local reserve) and the steps after it
// under a fresh deadline of the whole reserve (contract D15(d)): a pull
// ending just before the budget runs out is the registry's
// (image_unavailable) and cannot starve the local steps into a miner
// fault, while a local step slower than the reserve stays a fault.
func TestCreateSplitsTheCreateBudget(t *testing.T) {
	const budget, reserve = 900 * time.Millisecond, 300 * time.Millisecond
	neverStarts := func(c *engineContainer) (int, string) {
		c.Error = startFailure
		return http.StatusInternalServerError, startFailure
	}
	for _, test := range []struct {
		name      string
		pull      time.Duration
		refuse    func(*engineContainer) (int, string)
		startHeld time.Duration
		// slowDNS makes the registry host's resolution last until it is
		// given up on.
		slowDNS bool
		// want is "ready", a refusal code, or the miner fault.
		want string
	}{
		{name: "pull ends just inside its share", pull: budget - reserve - 40*time.Millisecond, want: "ready"},
		{name: "pull ends just inside its share, start uses most of the reserve",
			pull: budget - reserve - 40*time.Millisecond, startHeld: reserve - 100*time.Millisecond, want: "ready"},
		{name: "pull ends just inside its share, image never starts",
			pull: budget - reserve - 40*time.Millisecond, refuse: neverStarts, want: "image_unavailable"},
		// The pull would end 2 ms before the budget: past its share.
		{name: "pull runs past its share", pull: budget - 2*time.Millisecond, want: "image_unavailable"},
		{name: "pull runs past its share, image never starts", pull: budget - 2*time.Millisecond, refuse: neverStarts, want: "image_unavailable"},
		{name: "registry host resolves past the pull share", slowDNS: true, want: "image_unavailable"},
		{name: "local step slower than the reserve after a fast pull", startHeld: reserve + 150*time.Millisecond, want: "start sandbox"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHost(t)
			h.engine.pullDelay, h.engine.refuseStart = test.pull, test.refuse
			if test.startHeld > 0 {
				h.engine.holdStart = func(*engineContainer) <-chan struct{} { return heldFor(test.startHeld) }
			}
			b := h.backend()
			b.localReserve = reserve
			if test.slowDNS {
				b.lookup = func(ctx context.Context, _ string) ([]netip.Addr, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
			}
			lease := testLease(nil)
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			err := b.Create(ctx, instanceOf(lease), lease)
			switch {
			case test.want == "ready" && err != nil:
				t.Fatalf("create = %v, want ready", err)
			case test.want == "image_unavailable" && refusalCode(err) != "image_unavailable":
				t.Fatalf("create = %v, want image_unavailable", err)
			case test.want != "ready" && test.want != "image_unavailable" &&
				(err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), test.want)):
				t.Fatalf("create = %v, want a miner fault containing %q", err, test.want)
			}
		})
	}
}

// The reserve covers the D23 settle bound with margin: a never-started
// image whose runtime teardown takes most of the settle bound, after a
// pull that ended just inside its share, is still the image's.
func TestCreateBudgetCoversTheStartSettle(t *testing.T) {
	const reserve = startSettleBound + time.Second
	const budget = reserve + time.Second
	h := newHost(t)
	h.engine.pullDelay = budget - reserve - 100*time.Millisecond
	lease := testLease(nil)
	instance := instanceOf(lease)
	dir := filepath.Join(h.config.ProcRoot, "5000")
	h.engine.refuseStart = func(c *engineContainer) (int, string) {
		c.Error = startFailure
		writeFile(t, filepath.Join(dir, "cmdline"), "runsc\x00delete\x00"+containerIDOf(instance)+"\x00")
		writeFile(t, filepath.Join(dir, "cgroup"), "0::/mc-engine.slice/containerd.service\n")
		if err := os.Symlink(h.config.RunscPath, filepath.Join(dir, "exe")); err != nil {
			t.Error(err)
		}
		time.AfterFunc(startSettleBound-300*time.Millisecond, func() { _ = os.RemoveAll(dir) })
		return http.StatusInternalServerError, startFailure
	}
	b := h.backend()
	b.localReserve = reserve
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if err := b.Create(ctx, instance, lease); refusalCode(err) != "image_unavailable" {
		t.Fatalf("create = %v, want image_unavailable within the reserve", err)
	}
}

// A budget that leaves the pull no share is refused before anything is
// asked of the engine; an explicit cancellation still reaches the local
// steps, whose deadline does not derive from the budget.
func TestCreateBudgetEdges(t *testing.T) {
	t.Run("budget no larger than the reserve", func(t *testing.T) {
		h := newHost(t)
		b := h.backend()
		b.localReserve = time.Second
		lease := testLease(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		err := b.Create(ctx, instanceOf(lease), lease)
		if err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), "no pull share") {
			t.Fatalf("create = %v, want a miner fault naming the missing pull share", err)
		}
		if h.engine.pulls != 0 || len(h.engine.created) != 0 {
			t.Fatalf("engine pulled %d times and created %d containers", h.engine.pulls, len(h.engine.created))
		}
	})
	t.Run("cancellation during the pull", func(t *testing.T) {
		h := newHost(t)
		h.engine.pullDelay = 2 * time.Second
		b := h.backend()
		b.localReserve = 5 * time.Second
		lease := testLease(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		time.AfterFunc(200*time.Millisecond, cancel)
		begun := time.Now()
		err := b.Create(ctx, instanceOf(lease), lease)
		if !errors.Is(err, context.Canceled) || refusalCode(err) != "" || time.Since(begun) > time.Second {
			t.Fatalf("create = %v after %v, want the cancellation promptly, not a refusal", err, time.Since(begun))
		}
	})
	t.Run("cancellation during a local step", func(t *testing.T) {
		h := newHost(t)
		h.engine.holdStart = func(*engineContainer) <-chan struct{} { return heldFor(2 * time.Second) }
		b := h.backend()
		b.localReserve = 5 * time.Second
		lease := testLease(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		time.AfterFunc(200*time.Millisecond, cancel)
		begun := time.Now()
		err := b.Create(ctx, instanceOf(lease), lease)
		if !errors.Is(err, context.Canceled) || time.Since(begun) > time.Second {
			t.Fatalf("create = %v after %v, want the cancellation promptly", err, time.Since(begun))
		}
	})
}

// dockerd sends a pull's response headers only with its first progress
// line, after the registry-controlled ping, token and manifest steps, so
// the pull waits for them until its pull deadline, not for the local
// answer timeout; every local call keeps that timeout (lane 8 INT-34-01).
func TestCreatePullIsBoundedByItsShareNotTheAnswerTimeout(t *testing.T) {
	const budget, reserve, answer = 900 * time.Millisecond, 300 * time.Millisecond, 100 * time.Millisecond
	for _, test := range []struct {
		name          string
		pull, inspect time.Duration
		want          string
	}{
		{name: "daemon withholds the pull's headers within the share", pull: budget - reserve - 200*time.Millisecond, want: "ready"},
		{name: "daemon withholds the pull's headers past the share", pull: budget - 100*time.Millisecond, want: "image_unavailable"},
		{name: "local call waits longer than the answer timeout", inspect: answer + 150*time.Millisecond, want: "awaiting response headers"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHost(t)
			h.engine.pullDelay, h.engine.inspectDelay = test.pull, test.inspect
			b := h.backend()
			b.engine = newEngineWithAnswerTimeout(h.socket, answer)
			b.localReserve = reserve
			lease := testLease(nil)
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			err := b.Create(ctx, instanceOf(lease), lease)
			switch {
			case test.want == "ready" && err != nil:
				t.Fatalf("create = %v, want ready", err)
			case test.want == "image_unavailable" && refusalCode(err) != "image_unavailable":
				t.Fatalf("create = %v, want image_unavailable", err)
			case test.want != "ready" && test.want != "image_unavailable" &&
				(err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), test.want)):
				t.Fatalf("create = %v, want a miner fault containing %q", err, test.want)
			}
		})
	}
}

// A refused pull ending just inside its share still has its stored image
// removed under the fresh local deadline, even when the removal outlasts
// what is left of the share (lane 7 SR-34-01).
func TestCreateDiscardsARefusedPullUnderTheLocalReserve(t *testing.T) {
	const budget, reserve = 900 * time.Millisecond, 300 * time.Millisecond
	key := "docker.io/library/busybox@" + testImageDigest
	for name, refused := range map[string]func(*engineImage){
		"progress stream breaks off": func(i *engineImage) { i.PullMessages, i.PullBreakOff = i.PullMessages[:1], true },
		"download exceeds the image limit": func(i *engineImage) {
			i.PullMessages = []string{
				`{"id":"a","status":"Downloading","progressDetail":{"total":40000000}}`,
				`{"id":"b","status":"Downloading","progressDetail":{"total":40000000}}`,
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t)
			image := h.engine.catalog[key]
			refused(&image)
			h.engine.catalog[key] = image
			h.engine.pullDelay = budget - reserve - 40*time.Millisecond
			h.engine.imageRemovalDelay = 150 * time.Millisecond
			b := h.backend()
			b.localReserve = reserve
			lease := testLease(nil)
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			if err := b.Create(ctx, instanceOf(lease), lease); refusalCode(err) != "image_unavailable" {
				t.Fatalf("create = %v, want image_unavailable", err)
			}
			if len(h.engine.images) != 0 {
				t.Fatalf("refused pull left %d images", len(h.engine.images))
			}
		})
	}
}
