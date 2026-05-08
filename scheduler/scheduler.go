package scheduler

import (
	"time"
)

type SchedulerService interface {
	Start()
	Stop()
	ScheduleTask(task func(), at time.Time) error
	CancelScheduledTask()
	GetTaskScheduledAt() time.Time
}
