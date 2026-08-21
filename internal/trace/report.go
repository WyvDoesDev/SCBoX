package trace

// Report is a fully-serializable snapshot of an analysis result. The detonation
// runs inside the locked-down jail child; it sends a Report back to the parent
// over a pipe, and the parent renders from it. Every field is exported so the
// struct round-trips cleanly through gob/json.
type Report struct {
	Verdict Verdict
	Sources []SourceStat
	IOCs    map[string][]string
	Events  []Event
}

// Report snapshots everything the renderer needs from the tracer.
func (t *Tracer) Report() Report {
	return Report{
		Verdict: t.Verdict(),
		Sources: t.SourceStats(),
		IOCs:    t.IOCs().Snapshot(),
		Events:  t.Events(),
	}
}
