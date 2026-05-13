// Package scheduler provides a tiny "at-most-one task in flight"
// scheduler interface, with a gocron-backed implementation in
// scheduler/gocron. The SDK uses it to drive the auto-settle feature
// (one settle scheduled per wallet, rescheduled as fresher vtxos arrive),
// but the interface is intentionally generic — anything that needs
// "run this func at a future timestamp, cancellable, re-arm-able" can
// reuse it.
//
// # Contract
//
// The [SchedulerService] interface holds at most one pending task at a
// time:
//
//   - [SchedulerService.ScheduleTask](task, at) — schedules task for
//     execution at the absolute time `at`. If a task is already
//     scheduled, it's cancelled first (last-writer-wins). If `at` is in
//     the past, returns an error; if `at` is exactly now, runs task
//     synchronously and returns nil.
//   - [SchedulerService.CancelScheduledTask]() — cancels the pending
//     task if any; safe to call when nothing is scheduled.
//   - [SchedulerService.GetTaskScheduledAt]() — returns the next-run
//     time, or zero if nothing is pending.
//   - [SchedulerService.Start]() / [SchedulerService.Stop]() — start /
//     stop the background runner. Implementations may be stateful
//     across Stop/Start cycles, so callers should treat Stop as
//     terminal unless the implementation's docs say otherwise.
//
// # Implementation (scheduler/gocron)
//
// The gocron implementation wraps a [github.com/go-co-op/gocron]
// scheduler and tracks the single pending job alongside a
// context.CancelFunc:
//
//   - ScheduleTask cancels any prior pending job (firing the
//     CancelFunc and removing the job from gocron's queue) before
//     installing the new one. The new job runs at most once
//     (LimitRunsTo(1)) and clears itself from the service after
//     firing — so GetTaskScheduledAt returns zero post-fire.
//   - Stop cancels the pending job's context, removes the job from
//     gocron, stops the gocron runner, and clears its internal state.
//     A task already past its early-exit ctx.Done() check will still
//     run to completion — callers that need to fence task execution
//     against external state (e.g. a closed DB) must check inside the
//     task closure.
//   - The service is safe to use across goroutines; a single mutex
//     guards every public method.
//
// # Auto-settle (Wallet consumer)
//
// See arksdk's init.go: scheduleNextSettlement. The Wallet injects a
// scheduler at NewWallet time (defaulting to NewScheduler from
// scheduler/gocron), starts it on unlock, schedules a Settle task at
// ~90% of the earliest vtxo's remaining lifetime, and re-schedules
// every time a fresh Ark tx event arrives — the last-writer-wins
// behavior ensures the most recent expiry estimate always wins. Stop
// on the Wallet tears down the scheduler before closing the underlying
// store so a late-firing task can't hit a closed DB.
//
// Callers that don't want auto-settle pass arksdk.WithoutAutoSettle()
// at construction; the Wallet then nils out the scheduler entirely.
// Callers that want a custom scheduler (e.g. a remote / cluster-aware
// implementation) pass arksdk.WithScheduler(custom).
package scheduler
