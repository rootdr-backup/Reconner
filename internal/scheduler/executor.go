package scheduler

import "github.com/recon-platform/internal/tools"

func (s *Scheduler) GetExecutor() *tools.Executor {
	return s.executor
}
