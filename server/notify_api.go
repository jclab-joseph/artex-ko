package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// This file is the HTTP interface for the notification feature. All routes are mounted after requireAuth (see Handler()),
// consistent with the other management APIs.

// notify_api.go 가 HTTP 응답으로 돌려주는 사용자 노출 오류 문구다. 한국어 UI 에서 알림
// 설정 요청이 실패하면 이 문구가 그대로 토스트로 뜨므로 한국어로 둔다. 식별자(id)·JSON
// 필드명·enum 값(realtime·digest)·채널 종류 키는 사용자가 설정을 고치는 데 쓰는 값이라
// 원문 그대로 둔다. %s·%q 가 든 상수는 fmt.Sprintf 형식 문자열이다. 용어: channel→채널,
// notification→알림(크롬 nav "알림 발송"), delivery→전송, push mode→발송 모드. 로그·주석은 BRIEF
// 방침상 최하위라 이 묶음 밖이다.
const (
	notifyErrBadJSON         = "요청 본문이 올바른 JSON 형식이 아닙니다: "
	notifyErrKindInvalidFmt  = "채널 유형이 올바르지 않습니다. 가능한 값: %s"
	notifyErrNameMissing     = "채널 이름을 입력하세요"
	notifyErrNameEmpty       = "채널 이름은 비워 둘 수 없습니다"
	notifyErrModeInvalid     = "발송 모드가 올바르지 않습니다. 가능한 값: realtime / digest"
	notifyErrRateNegative    = "전송 제한 값은 음수일 수 없습니다"
	notifyErrChannelID       = "채널 id 가 올바르지 않습니다"
	notifyErrKindUnregFmt    = "채널 유형 %q 는 등록되어 있지 않습니다"
	notifyErrDeliveryID      = "전송 id 가 올바르지 않습니다"
	notifyErrChannelNotFound = "알림 채널을 찾을 수 없습니다"
)

// 채널 연결을 점검할 때 보내는 테스트 메시지 본문이다. 사용자가 등록한 채널로 실제 발송되므로
// 한국어로 두되, 받는 사람이 실제 취약점으로 오해하지 않도록 한눈에 테스트임이 드러나게 한다.
const (
	notifyTestName    = "테스트 메시지 · 채널 설정 정상"
	notifyTestClass   = "연결 테스트"
	notifyTestSummary = "ARTEX 알림 채널 테스트 메시지입니다. 이 메시지를 받으셨다면 채널 설정이 정상입니다."
)

// notifyChannelDTO is the external representation of a channel.
//
// Config is the **masked** config: credential fields are replaced with values that start with notify.MaskedPrefix.
// When the frontend submits a masked value back as-is, it means "this field was not changed", and the server keeps the stored value accordingly
// (see notify.MergeConfig).
type notifyChannelDTO struct {
	ID         int64          `json:"id"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Enabled    bool           `json:"enabled"`
	Mode       string         `json:"mode"`
	Config     map[string]any `json:"config"`
	Filter     notify.Filter  `json:"filter"`
	RatePerMin int            `json:"rate_per_min"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	// SecretKeys tells the frontend which fields are credentials, so it renders password boxes and the "leave blank to keep unchanged" hint.
	// Declared by the channel itself (notify.Channel.SecretKeys); the frontend does not hard-code channel knowledge.
	SecretKeys []string `json:"secret_keys"`
}

// notifyDeliveryDTO is the external representation of delivery history.
type notifyDeliveryDTO struct {
	ID          int64      `json:"id"`
	FindingID   int64      `json:"finding_id,string"`
	EventKind   string     `json:"event_kind"`
	ChannelID   int64      `json:"channel_id"`
	ChannelName string     `json:"channel_name"`
	ChannelKind string     `json:"channel_kind"`
	State       string     `json:"state"`
	Attempts    int        `json:"attempts"`
	LastError   string     `json:"last_error"`
	BatchID     *int64     `json:"batch_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	SentAt      *time.Time `json:"sent_at,omitempty"`
	NextAttempt time.Time  `json:"next_attempt_at"`
	// a summary of the message title, so the history list shows what was pushed without expanding.
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

func toNotifyChannelDTO(ch *db.NotificationChannel) notifyChannelDTO {
	var cfg map[string]any
	if len(ch.Config) > 0 {
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	secrets := []string{}
	if c, ok := notify.Get(ch.Kind); ok {
		secrets = c.SecretKeys()
	}
	return notifyChannelDTO{
		ID:         ch.ID,
		Name:       ch.Name,
		Kind:       ch.Kind,
		Enabled:    ch.IsEnabled(),
		Mode:       ch.Mode,
		Config:     notify.MaskConfig(ch.Kind, cfg),
		Filter:     notify.ParseFilter(ch.Filter),
		RatePerMin: ch.RatePerMin,
		CreatedAt:  ch.CreatedAt,
		UpdatedAt:  ch.UpdatedAt,
		SecretKeys: secrets,
	}
}

func toNotifyDeliveryDTO(dl *db.NotificationDelivery) notifyDeliveryDTO {
	snap, _ := parseSnapshot(dl)
	dto := notifyDeliveryDTO{
		ID:          dl.ID,
		FindingID:   dl.FindingID,
		EventKind:   dl.EventKind,
		ChannelID:   dl.ChannelID,
		ChannelName: dl.ChannelName,
		ChannelKind: dl.ChannelKind,
		State:       dl.State,
		Attempts:    dl.Attempts,
		LastError:   dl.LastError,
		BatchID:     dl.BatchID,
		CreatedAt:   dl.CreatedAt,
		SentAt:      dl.SentAt,
		NextAttempt: dl.NextAttemptAt,
		Severity:    snap.Severity,
	}
	if snap.Name != "" {
		dto.Title = snap.Name
	} else {
		dto.Title = snap.VulnClass
	}
	return dto
}

// notifyMeta returns the static metadata and global settings the notification page needs, all in one request,
// so the frontend does not make three requests just to render one dropdown.
func (s *Server) notifyMeta(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	kinds := make([]map[string]any, 0, len(notify.Kinds()))
	for _, k := range notify.Kinds() {
		ch, _ := notify.Get(k)
		kinds = append(kinds, map[string]any{
			"kind":                 k,
			"default_rate_per_min": ch.DefaultRatePerMin(),
			"secret_keys":          ch.SecretKeys(),
		})
	}
	baseURL, _, _ := pg.GetSetting(settingNotifyPublicBaseURL)
	digest, _, _ := pg.GetSetting(settingNotifyDigestMinutes)
	stats, err := pg.NotificationStatsSnapshot(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"kinds":               kinds,
		"enabled":             pg.GetBool(settingNotifyEnabled, true),
		"public_base_url":     baseURL,
		"digest_interval_min": digest,
		"defaults": map[string]any{
			"digest_interval_min": notifyDefaultDigestMinutes,
		},
		"stats": stats,
	})
}

func (s *Server) notifyListChannels(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	channels, err := pg.ListNotificationChannels(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]notifyChannelDTO, 0, len(channels))
	for _, ch := range channels {
		out = append(out, toNotifyChannelDTO(ch))
	}
	writeJSON(w, 200, map[string]any{"channels": out})
}

// notifyChannelRequest is the request body for creating/updating a channel.
//
// All business fields use pointers to distinguish "not sent" from "sent a zero value": under PATCH semantics,
// a field that was not sent must keep the stored value.
type notifyChannelRequest struct {
	Name       *string        `json:"name"`
	Kind       *string        `json:"kind"`
	Enabled    *bool          `json:"enabled"`
	Mode       *string        `json:"mode"`
	Config     map[string]any `json:"config"`
	Filter     *notify.Filter `json:"filter"`
	RatePerMin *int           `json:"rate_per_min"`
}

func (s *Server) notifyCreateChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req notifyChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, notifyErrBadJSON+err.Error())
		return
	}
	if req.Kind == nil || !notify.ValidKind(*req.Kind) {
		writeErr(w, 400, fmt.Sprintf(notifyErrKindInvalidFmt, strings.Join(notify.Kinds(), " / ")))
		return
	}
	name := ""
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if name == "" {
		writeErr(w, 400, notifyErrNameMissing)
		return
	}
	channel, _ := notify.Get(*req.Kind)
	if err := channel.Validate(req.Config); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ch := &db.NotificationChannel{
		Name:       name,
		Kind:       *req.Kind,
		Enabled:    req.Enabled,
		Mode:       db.NotifyModeRealtime,
		RatePerMin: channel.DefaultRatePerMin(),
	}
	if req.Mode != nil {
		if !db.ValidNotifyMode(*req.Mode) {
			writeErr(w, 400, notifyErrModeInvalid)
			return
		}
		ch.Mode = *req.Mode
	}
	if req.RatePerMin != nil {
		// Use the value as given when explicit — including 0, which means "no rate limit" and is a valid config.
		if *req.RatePerMin < 0 {
			writeErr(w, 400, notifyErrRateNegative)
			return
		}
		ch.RatePerMin = *req.RatePerMin
	}
	// Only a "missing field" applies the channel default. The default must be decided here, not in the db layer:
	// only the request body can distinguish "this field was not sent" from "0 was sent explicitly", and the two mean completely different things
	// (the former = use the default, the latter = no rate limit). The db layer treats 0 as unspecified too, which would make a no-rate-limit config unreachable.
	if req.RatePerMin == nil {
		ch.RatePerMin = channel.DefaultRatePerMin()
	}
	if req.Filter != nil {
		// On write, validate filter fields with restricted values (such as min_severity). See notify.Filter.Validate:
		// a typo in the threshold would silently disable the filter and push everything, so it must be caught at the entry point.
		if err := req.Filter.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		raw, _ := json.Marshal(req.Filter)
		ch.Filter = raw
	}
	rawCfg, _ := json.Marshal(req.Config)
	ch.Config = rawCfg

	id, err := pg.SaveNotificationChannel(r.Context(), ch)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}

func (s *Server) notifyUpdateChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, notifyErrChannelID)
		return
	}
	current, err := pg.NotificationChannelByID(r.Context(), id)
	if err != nil {
		notifyChannelLookupErr(w, err)
		return
	}
	var req notifyChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, notifyErrBadJSON+err.Error())
		return
	}

	// kind can be changed, but changing the type means the whole set of credential fields is replaced and cannot be merged with the old config.
	kind := current.Kind
	if req.Kind != nil {
		if !notify.ValidKind(*req.Kind) {
			writeErr(w, 400, fmt.Sprintf(notifyErrKindInvalidFmt, strings.Join(notify.Kinds(), " / ")))
			return
		}
		kind = *req.Kind
	}
	channel, _ := notify.Get(kind)

	var stored map[string]any
	if kind == current.Kind {
		if len(current.Config) > 0 {
			_ = json.Unmarshal(current.Config, &stored)
		}
	}
	if stored == nil {
		stored = map[string]any{}
	}
	// Use PrepareConfigUpdate rather than a bare MergeConfig: when the target address changes, the operator must re-confirm
	// the credential fields, otherwise "change only the address, keep the credentials" would send the real stored credentials to the new address.
	merged, err := notify.PrepareConfigUpdate(kind, stored, req.Config)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := channel.Validate(merged); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rawCfg, _ := json.Marshal(merged)

	ch := &db.NotificationChannel{
		ID:         id,
		Name:       current.Name,
		Kind:       kind,
		Enabled:    current.Enabled,
		Mode:       current.Mode,
		Config:     rawCfg,
		Filter:     current.Filter,
		RatePerMin: current.RatePerMin,
	}
	if req.Name != nil {
		if ch.Name = strings.TrimSpace(*req.Name); ch.Name == "" {
			writeErr(w, 400, notifyErrNameEmpty)
			return
		}
	}
	if req.Enabled != nil {
		ch.Enabled = req.Enabled
	}
	if req.Mode != nil {
		if !db.ValidNotifyMode(*req.Mode) {
			writeErr(w, 400, notifyErrModeInvalid)
			return
		}
		ch.Mode = *req.Mode
	}
	if req.RatePerMin != nil {
		if *req.RatePerMin < 0 {
			writeErr(w, 400, notifyErrRateNegative)
			return
		}
		ch.RatePerMin = *req.RatePerMin
	}
	if req.Filter != nil {
		if err := req.Filter.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		raw, _ := json.Marshal(req.Filter)
		ch.Filter = raw
	}

	// Go through SetNotificationChannelEnabled rather than SaveNotificationChannel,
	// so that "disable" also marks existing pending deliveries as skipped, avoiding receiving
	// a batch of stale backlogged messages on re-enable.
	enabledChanged := ch.Enabled != nil && current.Enabled != nil && *ch.Enabled != *current.Enabled
	if enabledChanged {
		// First persist the config update (with enabled at its old value, to avoid triggering the skip logic early),
		// then flip the toggle separately. There is no concurrency window between the two steps: this API is the only entry point that changes these two fields.
		prev := ch.Enabled
		ch.Enabled = current.Enabled
		if _, err := pg.SaveNotificationChannel(r.Context(), ch); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if err := pg.SetNotificationChannelEnabled(r.Context(), id, *prev); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"id": id})
		return
	}
	if _, err := pg.SaveNotificationChannel(r.Context(), ch); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}

func (s *Server) notifyDeleteChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, notifyErrChannelID)
		return
	}
	if err := pg.DeleteNotificationChannel(r.Context(), id); err != nil {
		notifyChannelLookupErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// notifyTestChannel sends one test message using the currently saved config.
//
// Call the channel's Send directly instead of going through the delivery queue: the point of a test is to immediately tell the user "whether this config can
// send", and going through the queue would hide the result in the delivery history, forcing the user to look it up again to know if it worked.
// So this API is **synchronous**, with the timeout bound decided by the notify package's HTTP client (15 seconds).
func (s *Server) notifyTestChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, notifyErrChannelID)
		return
	}
	ch, err := pg.NotificationChannelByID(r.Context(), id)
	if err != nil {
		notifyChannelLookupErr(w, err)
		return
	}
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		writeErr(w, 400, fmt.Sprintf(notifyErrKindUnregFmt, ch.Kind))
		return
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if err := channel.Validate(cfg); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	msg := notifyTestMessage(s.notifierBaseURL(pg))
	start := time.Now()
	// There is only one test message, so the delivered count is not needed here (the channel's length cap for a single message
	// is handled by truncation, with no segmentation).
	if _, err := channel.Send(r.Context(), cfg, msg); err != nil {
		// Return the channel's raw error faithfully to the user — it is their only clue for debugging the config.
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"latency_ms": time.Since(start).Milliseconds(),
	})
}

// notifyTestMessage builds the test message. It deliberately uses content that is obviously a test at a glance:
// whoever receives it should not mistake it for a real finding.
func notifyTestMessage(baseURL string) notify.Message {
	return notify.Message{
		Items: []notify.Item{{
			FindingID: 0,
			Name:      notifyTestName,
			VulnClass: notifyTestClass,
			Severity:  "low",
			Summary:   notifyTestSummary,
			Assets:    []string{"artex.example.com"},
			DetailURL: baseURL,
		}},
		HomeURL: baseURL,
	}
}

// notifierBaseURL reads the external address used for back-links.
func (s *Server) notifierBaseURL(pg *db.DB) string {
	v, _, _ := pg.GetSetting(settingNotifyPublicBaseURL)
	return trimTrailingSlash(v)
}

func (s *Server) notifyListDeliveries(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	f := db.NotificationDeliveryFilter{
		State:     r.URL.Query().Get("state"),
		EventKind: r.URL.Query().Get("event_kind"),
	}
	if v := r.URL.Query().Get("channel_id"); v != "" {
		f.ChannelID = int64(atoiDefault(v, 0))
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 50)
	items, total, err := pg.ListNotificationDeliveries(r.Context(), f, page, pageSize)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]notifyDeliveryDTO, 0, len(items))
	for _, dl := range items {
		out = append(out, toNotifyDeliveryDTO(dl))
	}
	writeJSON(w, 200, map[string]any{"deliveries": out, "total": total, "page": page, "page_size": pageSize})
}

func (s *Server) notifyRetryDelivery(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, notifyErrDeliveryID)
		return
	}
	if err := pg.RetryNotificationDelivery(r.Context(), id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// notifyChannelLookupErr translates "channel does not exist" into a 404, and other errors into 500.
func notifyChannelLookupErr(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrNotificationChannelNotFound) {
		writeErr(w, 404, notifyErrChannelNotFound)
		return
	}
	writeErr(w, 500, err.Error())
}
