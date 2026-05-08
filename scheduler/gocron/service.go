package cronScheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/go-sdk/scheduler"
	"github.com/go-co-op/gocron"
)

type service struct {
	scheduler *gocron.Scheduler
	job       *gocron.Job
	stopJob   func()
	started   bool
	mu        *sync.Mutex
}

func NewScheduler() scheduler.SchedulerService {
	svc := gocron.NewScheduler(time.UTC)
	return &service{
		scheduler: svc,
		mu:        &sync.Mutex{},
	}
}

func (s *service) ensureSchedulerLocked() {
	if s.scheduler != nil {
		return
	}
	s.scheduler = gocron.NewScheduler(time.UTC)
	if s.started {
		s.scheduler.StartAsync()
	}
}

func (s *service) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return
	}
	s.ensureSchedulerLocked()
	s.scheduler.StartAsync()
	s.started = true
}

func (s *service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.scheduler != nil {
		if s.job != nil {
			if s.stopJob != nil {
				s.stopJob()
			}
			s.scheduler.Remove(s.job)
		}
		s.scheduler.Stop()
		s.scheduler.Clear()
	}
	s.scheduler = nil
	s.job = nil
	s.stopJob = nil
	s.started = false
}

func (s *service) ScheduleTask(task func(), at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("invalid schedule time")
	}

	delay := time.Until(at)
	if delay < 0 {
		return fmt.Errorf("cannot schedule task in the past at %s", at.Format(time.RFC3339))
	}

	s.CancelScheduledTask()

	if delay == 0 {
		task()
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureSchedulerLocked()

	ctx, cancel := context.WithCancel(context.Background())
	job, err := s.scheduler.Every(delay).WaitForSchedule().LimitRunsTo(1).Do(func() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.mu.Lock()
		if ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		if s.scheduler != nil && s.job != nil {
			s.scheduler.Remove(s.job)
		}
		s.job = nil
		s.stopJob = nil
		s.mu.Unlock()

		task()
	})
	if err != nil {
		cancel()
		return err
	}

	s.job = job
	s.stopJob = cancel

	return err
}

// GetTaskScheduledAt returns the next scheduled task time.
func (s *service) GetTaskScheduledAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.job == nil {
		return time.Time{}
	}

	return s.job.NextRun()
}

func (s *service) CancelScheduledTask() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.job == nil {
		return
	}

	if s.stopJob != nil {
		s.stopJob()
	}
	if s.scheduler != nil {
		s.scheduler.Remove(s.job)
	}
	s.job = nil
	s.stopJob = nil
}
