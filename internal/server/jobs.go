package server

import (
	"context"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

// jobRunner runs periodic background jobs (purges, rotations...) until the
// context given to Start is cancelled. Register a job with
//
//	s.jobs.Every("name", interval, func(ctx context.Context) error { ... })
//
// from New or a register<Domain>Routes function; jobs registered after Start
// begin immediately. Names are unique: registering a name again is ignored,
// so registration may safely run more than once. A job runs once at start
// and then every interval; a run that panics or fails is logged and retried
// at the next tick. Each run gets a context cancelled on shutdown.
//
// Every replica runs every job, so jobs must be idempotent and safe to run
// concurrently with the same job elsewhere (a DELETE ... WHERE expired is).
//
// A nil *jobRunner (a Server built without New, as in tests) ignores
// registrations.
type jobRunner struct {
	mu      sync.Mutex
	jobs    map[string]*job
	ctx     context.Context
	started bool
	wg      sync.WaitGroup
}

type job struct {
	name     string
	interval time.Duration
	fn       func(context.Context) error
}

func newJobRunner() *jobRunner {
	return &jobRunner{jobs: map[string]*job{}}
}

// Every registers fn to run every interval under name.
func (j *jobRunner) Every(name string, interval time.Duration, fn func(context.Context) error) {
	if j == nil || fn == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, dup := j.jobs[name]; dup {
		return
	}
	jb := &job{name: name, interval: interval, fn: fn}
	j.jobs[name] = jb
	if j.started {
		j.launchLocked(jb)
	}
}

// Start launches every registered job; they stop when ctx is cancelled.
// Calling Start again has no effect.
func (j *jobRunner) Start(ctx context.Context) {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.started {
		return
	}
	j.started = true
	j.ctx = ctx
	for _, jb := range j.jobs {
		j.launchLocked(jb)
	}
}

// Wait blocks until every job goroutine has returned (after the Start
// context is cancelled).
func (j *jobRunner) Wait() {
	if j == nil {
		return
	}
	j.wg.Wait()
}

func (j *jobRunner) launchLocked(jb *job) {
	ctx := j.ctx
	j.wg.Add(1)
	go func() {
		defer j.wg.Done()
		t := time.NewTicker(jb.interval)
		defer t.Stop()
		for {
			runJob(ctx, jb)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func runJob(ctx context.Context, jb *job) {
	if ctx.Err() != nil {
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("job %s panicked: %v\n%s", jb.name, rec, debug.Stack())
		}
	}()
	if err := jb.fn(ctx); err != nil && ctx.Err() == nil {
		log.Printf("job %s failed: %v", jb.name, err)
	}
}
