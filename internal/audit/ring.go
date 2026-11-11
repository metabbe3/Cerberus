package audit

// ring is a fixed-size circular buffer of Events, safe only behind Logger.mu.
type ring struct {
	buf  []Event
	next int  // next write index
	full bool // buf has wrapped at least once
}

func newRing(size int) *ring {
	if size <= 0 {
		size = 1
	}
	return &ring{buf: make([]Event, size)}
}

// add appends ev, overwriting the oldest entry once full.
func (r *ring) add(ev Event) {
	r.buf[r.next] = ev
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

// recent returns up to n events, newest first.
func (r *ring) recent(n int) []Event {
	count := r.next
	if r.full {
		count = len(r.buf)
	}
	if n < count {
		count = n
	}
	out := make([]Event, 0, count)
	for i := range count {
		out = append(out, r.buf[(r.next-1-i+len(r.buf))%len(r.buf)])
	}
	return out
}

// since returns events with ID > lastID in chronological order (oldest first).
func (r *ring) since(lastID int64) []Event {
	count := r.next
	if r.full {
		count = len(r.buf)
	}
	out := make([]Event, 0, count)
	start := (r.next - count + len(r.buf)) % len(r.buf)
	for i := 0; i < count; i++ {
		ev := r.buf[(start+i)%len(r.buf)]
		if ev.ID > lastID {
			out = append(out, ev)
		}
	}
	return out
}

func (r *ring) erase(id int64) {
	for i := range r.buf {
		if r.buf[i].ID == id {
			r.buf[i].Args = map[string]any{"_erased": true}
		}
	}
}
