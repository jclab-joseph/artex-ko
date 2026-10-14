package notify

// Snapshot is the contract for the notification_events.snapshot JSONB column. The writer is the
// finding-persistence transaction in the db layer; the readers are the delivery engine and filter
// matching in the server layer. It is defined in this package because it is the payload of the
// "notification domain": db only serializes it and does not understand the field meanings.
//
// Why finding fields are stored redundantly instead of being re-queried at render time: a finding
// may later be renamed, re-graded, or have its status changed, whereas the pushed content should
// reflect the conclusion **at the time of the event** — a re-query would yield the dangerously
// misleading "later changed to low". Also, fan-out and rendering therefore need not JOIN the
// findings/tasks/assets tables.
type Snapshot struct {
	// Event type: finding_created / finding_status_changed
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// Non-empty only when kind=finding_status_changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item is a single finding awaiting push, for channel rendering.
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets are the resolved asset display names (e.g. domain/IP). Filled in by the
	// server layer — this package does not touch the database and cannot get the names.
	Assets []string
	// DetailURL is the back-link to the finding detail; empty means public_base_url is not configured, so it is omitted when rendering.
	DetailURL string
	// For status-change events only; when both are non-empty it renders as "pending → fixed".
	FromStatus string
	ToStatus   string
}

// IsStatusChange reports whether this item is a status-change event.
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title returns the item's display title: it prefers the manually assigned name, falls back to the
// vulnclass, and uses a placeholder when both are empty — it never outputs an empty title.
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(이름 없는 취약점)"
}

// Message is the complete content of one channel send.
type Message struct {
	// Length is 1 for a single push; for a digest push it is a whole batch.
	// An empty slice is illegal; the caller must guarantee at least one item.
	Items []Item
	// When Batch=true it renders as a digest message (different title, with time window and count).
	Batch bool
	// WindowMinutes is the digest period (minutes), used only when Batch=true for the phrase "last N minutes".
	// Deliberately passed explicitly from config instead of computing time.Since at render time: rendering stays deterministic, which is testable.
	WindowMinutes int
	// HomeURL is the platform dashboard address (global public_base_url); empty means no dashboard entry is included.
	HomeURL string
}
