package types

import "time"

type Scheduler interface {
	Start()
	Stop()
	ScheduleTaskAtTime(at time.Time, taskFunc func()) error
	ScheduleTaskAtHeight(target uint32, taskFunc func()) error
}
