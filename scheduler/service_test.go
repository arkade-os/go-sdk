package scheduler_test

import (
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/scheduler"
	cronScheduler "github.com/arkade-os/go-sdk/scheduler/gocron"
	"github.com/stretchr/testify/require"
)

var schedulerTypes = map[string]func() scheduler.SchedulerService{
	"gocron": func() scheduler.SchedulerService {
		return cronScheduler.NewScheduler()
	},
}

func TestScheduleTask(t *testing.T) {
	for schedulerType, newScheduler := range schedulerTypes {
		t.Run(schedulerType, func(t *testing.T) {
			t.Run("schedule next settlement", func(t *testing.T) {
				svc := newScheduler()
				svc.Start()
				defer svc.Stop()

				// Test scheduling in the future
				done := make(chan bool)
				task := func() {
					go func() {
						done <- true
					}()
				}

				// Schedule 5 second in the future
				nextTime := time.Now().Add(5 * time.Second)
				now := time.Now()
				err := svc.ScheduleTask(task, nextTime)
				require.NoError(t, err)

				// Verify next settlement time
				nextSettlement := svc.GetTaskScheduledAt()
				require.False(t, nextSettlement.IsZero())
				require.True(t, nextSettlement.After(now))
				require.True(t, nextSettlement.Before(
					now.Add(5*time.Second).Add(1*time.Millisecond),
				))

				// Wait for the job to execute
				select {
				case <-done:
					require.True(t, svc.GetTaskScheduledAt().IsZero())
				case <-time.After(10 * time.Second):
					require.Fail(t, "job did not execute within expected time")
				}

				// verify it won't run again
				select {
				case <-done:
					require.Fail(t, "job executed again")
				case <-time.After(10 * time.Second):
					// Job did not execute again
				}

			})

			t.Run("schedule settlement in the past", func(t *testing.T) {
				svc := newScheduler()
				svc.Start()
				defer svc.Stop()

				executed := false
				task := func() {
					executed = true
				}

				// Try to schedule in the past
				pastTime := time.Now().Add(-1 * time.Hour)
				err := svc.ScheduleTask(task, pastTime)
				require.Error(t, err)
				require.False(t, executed)
			})

			t.Run("schedule settlement for now", func(t *testing.T) {
				svc := newScheduler()
				svc.Start()
				defer svc.Stop()

				done := make(chan bool)
				task := func() {
					done <- true
				}

				// Schedule for immediate execution (add a small buffer to ensure it's not considered past)
				err := svc.ScheduleTask(task, time.Now().Add(100*time.Millisecond))
				require.NoError(t, err)

				select {
				case <-done:
					// Job executed successfully
				case <-time.After(1 * time.Second):
					require.Fail(t, "job did not execute within expected time")
				}
			})
		})
	}
}

func TestCancelScheduledTask(t *testing.T) {
	for schedulerType, newScheduler := range schedulerTypes {
		t.Run(schedulerType, func(t *testing.T) {
			svc := newScheduler()
			svc.Start()
			defer svc.Stop()

			done := make(chan bool)
			task := func() {
				go func() {
					done <- true
				}()
			}

			// Schedule 5 second in the future
			nextTime := time.Now().Add(5 * time.Second)
			now := time.Now()
			err := svc.ScheduleTask(task, nextTime)
			require.NoError(t, err)

			// Verify next settlement time
			nextSettlement := svc.GetTaskScheduledAt()
			require.False(t, nextSettlement.IsZero())
			require.True(t, nextSettlement.After(now))
			require.True(t, nextSettlement.Before(now.Add(5*time.Second).Add(1*time.Millisecond)))

			time.Sleep(time.Second)

			svc.CancelScheduledTask()
			nextSettlement = svc.GetTaskScheduledAt()
			require.True(t, nextSettlement.IsZero())

			// Wait for the job to execute
			select {
			case <-done:
				require.Fail(t, "job shouldn't have been executed")
			case <-time.After(10 * time.Second):
				// Job did not execute because it was indeed cancelled.
			}
		})
	}
}

func TestSchedulerRestart(t *testing.T) {
	for schedulerType, newScheduler := range schedulerTypes {
		t.Run(schedulerType, func(t *testing.T) {
			svc := newScheduler()
			defer svc.Stop()

			for i := 0; i < 3; i++ {
				svc.Start()

				done := make(chan struct{}, 1)
				err := svc.ScheduleTask(func() {
					done <- struct{}{}
				}, time.Now().Add(100*time.Millisecond))
				require.NoError(t, err)

				select {
				case <-done:
				case <-time.After(time.Second):
					require.Fail(t, "job did not execute after scheduler restart")
				}

				svc.Stop()
				require.True(t, svc.GetTaskScheduledAt().IsZero())
			}
		})
	}
}
