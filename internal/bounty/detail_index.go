package bounty

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	detailIndexWorkers = 4
	detailRetryDelay   = 15 * time.Minute
	detailIndexTimeout = 45 * time.Minute
)

// DetailIndexStatus describes the background catalog-scope index used by
// scope-derived filters. Counts refer to the current (or most recent) pass.
type DetailIndexStatus struct {
	Running     bool       `json:"running"`
	Total       int        `json:"total"`
	Pending     int        `json:"pending"`
	Completed   int        `json:"completed"`
	Failed      int        `json:"failed"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

func (s *Service) DetailIndexStatus() DetailIndexStatus {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	return s.indexState
}

// StartDetailIndex indexes previously unopened live programs with a small
// worker pool. It is idempotent while a pass is running and deliberately
// detached from the list request so navigation cannot cancel the catalog job.
func (s *Service) StartDetailIndex() DetailIndexStatus {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	if s.indexState.Running {
		return s.indexState
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ids, err := s.unindexedProgramIDs(ctx, time.Now())
	cancel()
	if err != nil {
		s.indexState.LastError = err.Error()
		return s.indexState
	}
	if len(ids) == 0 {
		return s.indexState
	}
	now := time.Now().UTC()
	s.indexState = DetailIndexStatus{Running: true, Total: len(ids), Pending: len(ids), StartedAt: &now}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), detailIndexTimeout)
		defer cancel()
		s.runDetailIndex(ctx, ids, detailIndexWorkers)
	}()
	return s.indexState
}

func (s *Service) unindexedProgramIDs(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM bounty_programs
		WHERE status='live' AND detail_synced_at IS NULL ORDER BY provider,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, 256)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if retryAt, exists := s.indexRetry[id]; exists && now.Before(retryAt) {
			continue
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Service) runDetailIndex(ctx context.Context, ids []string, workers int) {
	if workers < 1 {
		workers = 1
	}
	if workers > len(ids) {
		workers = len(ids)
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				err := s.ensureDetails(ctx, id, detailRefreshAge)
				s.indexMu.Lock()
				s.indexState.Pending--
				if err != nil {
					s.indexState.Failed++
					s.indexRetry[id] = time.Now().Add(detailRetryDelay)
				} else {
					s.indexState.Completed++
					delete(s.indexRetry, id)
				}
				s.indexMu.Unlock()
			}
		}()
	}
sendLoop:
	for _, id := range ids {
		select {
		case jobs <- id:
		case <-ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()

	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	if unprocessed := s.indexState.Pending; unprocessed > 0 {
		s.indexState.Failed += unprocessed
		s.indexState.Pending = 0
	}
	s.indexState.Running = false
	now := time.Now().UTC()
	s.indexState.CompletedAt = &now
	if ctx.Err() != nil {
		s.indexState.LastError = ctx.Err().Error()
	} else if s.indexState.Failed > 0 {
		s.indexState.LastError = fmt.Sprintf("%d program scope fetches failed and will retry later", s.indexState.Failed)
	}
}
