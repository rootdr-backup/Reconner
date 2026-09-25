package scanner

import "context"

// CoverageMetric is one durable, monotonically increasing module measurement.
// It deliberately describes execution rather than marketing coverage: scanners
// report what they discovered, admitted, attempted and proved or rejected.
type CoverageMetric string

const (
	CoverageDiscovered CoverageMetric = "discovered"
	CoverageEligible   CoverageMetric = "eligible"
	CoverageAttempted  CoverageMetric = "attempted"
	CoverageCandidate  CoverageMetric = "candidate"
	CoverageConfirmed  CoverageMetric = "confirmed"
	CoverageRejected   CoverageMetric = "rejected"
	CoverageBlocked    CoverageMetric = "blocked"
	CoverageError      CoverageMetric = "error"
)

type coverageReporterKey struct{}

// WithCoverageReporter attaches the scheduler's durable phase-ledger writer.
// Scanner packages remain independent of scheduler/database layout and tests can
// install a lightweight recorder without opening SQLite.
func WithCoverageReporter(ctx context.Context, reporter func(CoverageMetric, int64)) context.Context {
	if ctx == nil || reporter == nil {
		return ctx
	}
	return context.WithValue(ctx, coverageReporterKey{}, reporter)
}

// RecordCoverage is concurrency-safe when the installed reporter is. Counts are
// deltas so workers can report progress without coordinating a final snapshot.
func RecordCoverage(ctx context.Context, metric CoverageMetric, delta int64) {
	if ctx == nil || delta <= 0 {
		return
	}
	reporter, _ := ctx.Value(coverageReporterKey{}).(func(CoverageMetric, int64))
	if reporter != nil {
		reporter(metric, delta)
	}
}
