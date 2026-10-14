package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// Global setting keys (stored in the settings key-value table; no dedicated table needed).
const (
	// settingNotifyEnabled is the master switch for notifications. Default on: it is a
	// one-click kill switch for maintenance windows, not the feature's enablement
	// condition — the real enablement condition is "whether any channel is configured".
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL is the externally reachable address used to build deep
	// links to a finding's detail page (e.g. https://artex.example.com). Left empty,
	// messages carry no deep-link button. The project has no reusable external-address
	// setting, so this adds one.
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes is the digest-mode interval (minutes).
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick is the delivery engine's polling interval. 3 seconds is the ceiling on
	// the engine's realtime latency, and the main source of delay between "finding
	// persisted" and "message reaching the IM".
	notifyTick = 3 * time.Second
	// notifyBackgroundDisabledEnv 가 설정되면 서버가 백그라운드 전달 루프
	// (newNotifier(s).Run)를 띄우지 않는다. 통합 테스트는 stepRealtime·stepDigest 를
	// 직접 호출해 분배 결과를 결정론적으로 검증하는데, 3 초 주기의 백그라운드 루프가
	// 같은 채널을 동시에 처리하면 집계가 타이밍에 따라 흔들린다. 이를 막기 위한
	// 테스트 전용 스위치이며, 변수가 없으면 평소대로 기동한다(프로덕션 동작 불변).
	notifyBackgroundDisabledEnv = "ARTEX_NOTIFY_BACKGROUND_DISABLED"
	// notifyLease is the lease duration taken when claiming a delivery. It must be
	// significantly larger than a single delivery's worst-case cost (the notify package's
	// HTTP client times out at 15 seconds), or the same row can be delivered by two
	// dispatchers at once.
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick caps how many events are fanned out per tick, so enabling a
	// channel for the first time does not expand the entire historical backlog into
	// delivery tasks at once.
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes is the default digest interval.
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick is the per-tick delivery cap for a channel with no rate
	// limit. It exists to stop "a channel configured with no limit + a single scan that
	// turns up thousands of findings" from dragging one loop iteration into a long block.
	notifyUnlimitedBurstPerTick = 50
	// notifyMaxSendsPerChannelPerTick is the most deliveries a single channel sends per
	// tick.
	//
	// This cap is derived backwards from the **lease duration**: claiming a row stamps it
	// with a lease (notifyLease = 3 minutes), and if one tick serially delivers enough
	// rows that the worst-case cost exceeds the lease, the last few expire before they
	// are sent. Within one process this is harmless (Run is a single goroutine running
	// serially; ticks never re-enter), but with **two processes on the same database**
	// the peer re-claims the lease-expired rows and sends them again, double-increments
	// attempts, and judges them failed while the original process is still delivering.
	//
	// The value: 3-minute lease / 30-second per-send timeout = 6 would use up the lease
	// **exactly**, with zero margin, so it is not allowed; 5 keeps the worst case at 150
	// seconds, leaving 30 seconds of margin. TestNotifyTickBudgetFitsWithinLease pins this
	// relation down — changing notifyLease, notifySendTimeout, or this value alone breaks
	// that assertion.
	notifyMaxSendsPerChannelPerTick = 5
	// notifySendTimeout is the timeout for a single delivery. It also determines the
	// previous constant's value: their product must not exceed notifyLease, see
	// TestNotifyTickBudgetFitsWithinLease.
	notifySendTimeout = 30 * time.Second
)

// notifyBackoff is the backoff sequence for failed retries, indexed by attempts made.
// 3 chances (including the first) correspond to db.MaxNotifyAttempts; the two must be
// changed together.
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

// 전달 실패·지연 사유. notification_deliveries.last_error 에 저장되어
// notify_api.go 의 전달 이력 응답을 거쳐 알림 페이지 「전달 기록」 표(delivery-list.tsx)에
// 그대로 표시된다. 따라서 사용자 노출 문구라 한국어로 둔다(진단 로그 log.Printf 는 원문 보존, Z2).
const (
	errDeliveryChannelKindUnregistered = "등록되지 않은 채널 유형입니다: %q"
	errDeliverySnapshotUnrenderable    = "이벤트 스냅샷을 해석하지 못해 이 취약점을 메시지로 만들지 못했습니다"
	errDeliveryChannelLengthCapped     = "이 메시지가 채널 길이 상한에 도달해 앞의 %d건만 전송했고, 나머지는 다음 배치로 미룹니다"
	errDeliveryNoDeliveredCount        = "채널이 전송 건수를 보고하지 않았습니다(delivered=%d)"
	errDeliveryRetryExhausted          = "%d회 재시도 후에도 실패했습니다: %s"
	errDeliverySnapshotEmpty           = "전달 항목 #%d 의 이벤트 스냅샷이 비어 있습니다"
	errDeliverySnapshotParse           = "전달 항목 #%d 의 이벤트 스냅샷을 해석하지 못했습니다: %w"
	errDeliveryBatchAllUnparseable     = "요약 배치의 전달 %d건을 모두 해석하지 못했습니다"
)

// Notifier is the delivery engine for finding notifications.
//
// It runs as an independent goroutine alongside the Scheduler (see server.New). It
// deliberately does not reuse the Scheduler's tick: notifications' realtime requirement
// (3 seconds) differs from the triggers' business cadence, and a failure in one does not
// implicate the other — a stuck notification must not affect agent triggers.
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu guards buckets. Channels are few and contention is low, so one mutex is enough;
	// a finer-grained structure is not worth it here.
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket is a single channel's token bucket.
//
// A token bucket is used instead of a "count per minute then reset" sliding window
// because the latter has nasty edge effects: sending 20 at the end of one window and 20
// the very next instant is 40 in one second to the platform, which gets rate-limited; a
// token bucket refills at a constant rate and naturally avoids such bursts.
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run loops until ctx is done. Started once by server.New.
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step runs one round: first fan out new events, then deliver the tasks that are due.
//
// A failure in any step only logs and does not break the loop — a notification-system
// failure must never escalate into a process-level problem. Each tick is independent; the
// next round retries naturally.
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] failed to fan out events: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] failed to read channels: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// The token bucket meters **message count** (equivalent to HTTP request count),
		// not finding count. In realtime mode the two are the same (one finding, one
		// message); in digest mode a whole batch of findings is combined into one message,
		// so it consumes only one token.
		//
		// Both modes ask the token bucket first and only then claim against the budget —
		// the order must not be reversed, or deliveries blocked by the rate limiter have
		// already burned a retry.
		now := time.Now()
		if ch.Mode == db.NotifyModeDigest {
			tokens, claimLimit := digestTickPlan()
			if n.takeTokens(ch.ID, ch.RatePerMin, tokens, now) <= 0 {
				continue
			}
			n.stepDigest(ctx, ch, claimLimit, baseURL)
			continue
		}
		allow := n.takeTokens(ch.ID, ch.RatePerMin, notifyMaxSendsPerChannelPerTick, now)
		if allow <= 0 {
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// digestTickPlan returns a digest channel's token cost for this round and the upper bound
// on batch size.
//
// The two return values are **two different dimensions**, which is exactly why this is its
// own function:
//
//   - tokens is message count. A batch of findings is combined into one message and one
//     HTTP request, so it is always 1. rate_per_min therefore still applies to digests
//     (at most this many digest messages per minute).
//   - claimLimit is the most findings this batch may hold. It is bounded only by a memory
//     ceiling, unrelated to the request budget.
//
// To make rate_per_min apply to digests, the per-tick request budget
// (notifyMaxSendsPerChannelPerTick, derived backwards from the lease) was once passed
// straight down as the batch size. The result: a rate_per_min=20 channel refilled only 1
// token per 3-second tick, so each digest message held only 1 finding — the digest
// degenerated into "realtime push with digest wording", and the reader received a stream
// of "1 new finding in the last 30 minutes", while db.MaxDigestBatchSize was never
// reachable.
//
// This symptom is hard to catch in end-to-end tests (the existing cases all pass a
// large-enough limit to stepDigest by hand, bypassing the budget math in step), so the
// decision is captured here and pinned by
// TestDigestTickPlanDecouplesBatchSizeFromSendBudget.
func digestTickPlan() (tokens, claimLimit int) {
	return 1, db.MaxDigestBatchSize
}

// stepRealtime claims and delivers a channel's realtime tasks, one finding per message.
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] failed to claim realtime deliveries channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf(trMsg(errDeliveryChannelKindUnregistered), ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// A render failure is a local-data problem; retrying will not help.
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest aggregates a channel's pending deliveries into one message when the batch is due.
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] failed to check digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] failed to claim digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf(trMsg(errDeliveryChannelKindUnregistered), ch.Kind))
		return
	}
	msg, included, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	// Deliveries whose snapshot is broken and did not make it into the message must be
	// failed explicitly. Otherwise they stay outside included — neither in the message nor
	// in the failure list — and on a successful send the later batch marking skips their
	// state, leaving them stuck in sending until the lease expires and they are re-claimed
	// repeatedly.
	if skipped := excludeDeliveries(deliveries, included); len(skipped) > 0 {
		reason := errDeliverySnapshotUnrenderable
		if fErr := n.pg.FailDeliveries(ctx, deliveryIDs(skipped), reason); fErr != nil {
			log.Printf("[notify] failed to mark bad-snapshot deliveries channel=%s ids=%v: %v", ch.Kind, deliveryIDs(skipped), fErr)
		}
		log.Printf("[notify] skipped %d deliveries with unparseable snapshots channel=%d", len(skipped), ch.ID)
	}
	// Hand only the ones that made it into the message to send: included[i] corresponds
	// strictly to msg.Items[i], and send relies on that correspondence to map "the channel
	// reported it fit the first K" onto the right delivery rows.
	n.send(ctx, channel, cfg, msg, included)
}

// send delivers and transitions state according to the result.
//
// One batch of deliveries (possibly dozens in digest mode) shares a single send result:
// either delivered, or the whole batch is retried. There is no per-item retry — the digest
// message is one message, and resending part of it would scramble the batch semantics.
//
// The one exception is **segmentation caused by a channel length cap**: when the channel
// reports it actually fit only the first K, item K+1 onward must be held for the next
// batch rather than marked successful along with the rest. Otherwise the truncated
// findings are neither in the message nor in the failure list, and vanish entirely.
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	// Cap a single delivery so one stuck channel does not drag the rest of this round's channels with it.
	sendCtx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	delivered, err := channel.Send(sendCtx, cfg, msg)
	if err == nil && delivered > 0 {
		if delivered > len(deliveries) {
			// The channel-reported count can never exceed the number of deliveries; if it
			// does, the render layer miscounted — treat it as all delivered and record the
			// problem, which beats corrupting the records.
			log.Printf("[notify] channel reported delivered count %d exceeds delivery count %d channel=%s, treating as all delivered",
				delivered, len(deliveries), channel.Kind())
			delivered = len(deliveries)
		}
		sent, rest := deliveries[:delivered], deliveries[delivered:]
		if err := n.pg.MarkDeliveriesSent(ctx, deliveryIDs(sent)); err != nil {
			log.Printf("[notify] failed to mark deliveries sent channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(sent), err)
		}
		if len(rest) > 0 {
			// This message hit the channel length cap: the rest go straight back to the
			// queue for the next tick to continue sending. Use DeferDeliveries rather than
			// RescheduleDeliveries — this is not a failure and must not consume retry budget
			// (claiming already optimistically +1'd it, and that is undone there).
			if err := n.pg.DeferDeliveries(ctx, deliveryIDs(rest),
				fmt.Sprintf(trMsg(errDeliveryChannelLengthCapped), delivered)); err != nil {
				log.Printf("[notify] failed to queue segmented continuation channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(rest), err)
			}
		}
		return
	}
	if err == nil {
		// The channel neither errored nor reported how many it delivered. Treat it as a
		// failure (go through backoff) so this delivery is not re-claimed forever and never
		// marked.
		err = fmt.Errorf(trMsg(errDeliveryNoDeliveredCount), delivered)
	}

	// Failure handling is decided **per item**, not by taking the batch's maximum attempt
	// count.
	//
	// It used to be `if maxAttempts(deliveries) >= MaxNotifyAttempts`, failing the whole
	// batch, but items in a batch do not share the same attempt count: one old delivery
	// already retried twice (attempts=2) would drag a brand-new delivery (attempts=1) in
	// the same batch into failed — the new finding is permanently lost without a single
	// retry used, exactly the opposite of the intent "don't let old rows pull new ones
	// under".
	permanent := notify.IsPermanent(err)
	var failIDs, exhaustedIDs []int64
	byDelay := map[time.Duration][]int64{}
	for _, dl := range deliveries {
		switch {
		case permanent:
			failIDs = append(failIDs, dl.ID)
		case dl.Attempts >= db.MaxNotifyAttempts:
			exhaustedIDs = append(exhaustedIDs, dl.ID)
		default:
			delay := notifyBackoff[min(dl.Attempts, len(notifyBackoff)-1)]
			byDelay[delay] = append(byDelay[delay], dl.ID)
		}
	}

	if len(failIDs) > 0 {
		if fErr := n.pg.FailDeliveries(ctx, failIDs, err.Error()); fErr != nil {
			log.Printf("[notify] error marking failed state channel=%s ids=%v: %v", channel.Kind(), failIDs, fErr)
		}
	}
	if len(exhaustedIDs) > 0 {
		reason := fmt.Sprintf(trMsg(errDeliveryRetryExhausted), db.MaxNotifyAttempts, err)
		if fErr := n.pg.FailDeliveries(ctx, exhaustedIDs, reason); fErr != nil {
			log.Printf("[notify] error marking failed state channel=%s ids=%v: %v", channel.Kind(), exhaustedIDs, fErr)
		}
	}
	// Reschedule grouped by delay: with only 3 backoff tiers the group count is naturally
	// small, so there is no need to issue a separate UPDATE per item (which would turn a
	// 500-item batch into 500 round trips).
	for delay, group := range byDelay {
		if rErr := n.pg.RescheduleDeliveries(ctx, group, delay, err.Error()); rErr != nil {
			log.Printf("[notify] failed to reschedule deliveries channel=%s ids=%v: %v", channel.Kind(), group, rErr)
		}
	}
	if len(failIDs)+len(exhaustedIDs) > 0 {
		log.Printf("[notify] delivery failed channel=%d kind=%s permanent=%d retries-exhausted=%d pending-retry=%d: %s",
			deliveries[0].ChannelID, channel.Kind(), len(failIDs), len(exhaustedIDs), len(byDelay), err)
	}
}

// excludeDeliveries returns the members of all not in keep (compared by pointer identity).
// Used to find the deliveries that "did not make it into the message" — they must be
// handled explicitly and cannot be left in a gray area.
func excludeDeliveries(all, keep []*db.NotificationDelivery) []*db.NotificationDelivery {
	inKeep := make(map[*db.NotificationDelivery]bool, len(keep))
	for _, dl := range keep {
		inKeep[dl] = true
	}
	var out []*db.NotificationDelivery
	for _, dl := range all {
		if !inKeep[dl] {
			out = append(out, dl)
		}
	}
	return out
}

// adapt fetches the channel implementation and parses its config.
// ok=false means the kind is unregistered; the delivery should be failed outright rather
// than retried forever.
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// On a config parse failure, hand back an empty map: the channel's own Validate
		// will report "which field is missing", and that error guides the user to a fix
		// better than a JSON parse error.
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle renders a single-finding message.
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch renders a digest message. It parses snapshots one by one — if one is bad it
// skips only that one, rather than letting it sink the whole digest.
//
// The returned included and msg.Items correspond **strictly one-to-one** (the i-th
// delivery ↔ the i-th item). This correspondence is a hard requirement: the caller marks
// the first K deliveries sent based on "the channel reported it fit the first K". If a bad
// snapshot is skipped here without also removing the skipped delivery from included, the
// indices shift — a bad item that should have failed gets marked sent, and a good item is
// misjudged as not delivered. The bad ones are failed explicitly by the caller, see
// stepDigest.
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, []*db.NotificationDelivery, error) {
	items := make([]notify.Item, 0, len(deliveries))
	included := make([]*db.NotificationDelivery, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			// A bad snapshot goes neither into the message nor into included — its handling
			// is the caller's responsibility (fail it explicitly, rather than sneaking it
			// through among the "delivered").
			log.Printf("[notify] skipped unparseable snapshot in digest batch delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, nil, err
		}
		items = append(items, item)
		included = append(included, dl)
	}
	if len(items) == 0 {
		return notify.Message{}, nil, fmt.Errorf(trMsg(errDeliveryBatchAllUnparseable), len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, included, nil
}

// itemFor renders an event snapshot into a pushable item, resolving asset names and the
// detail deep link along the way.
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// An asset-name resolution failure must not block the push: missing a name is far
		// lighter than missing the notification entirely — the message just has one fewer
		// asset line.
		log.Printf("[notify] failed to resolve asset names finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// The detail-page route is in web/src/app/(main)/function/findings/detail/page.tsx;
		// it reads the finding id from the id query parameter.
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens takes **at most want** tokens from the channel's token bucket and returns the
// number actually taken.
//
// One token = one message (one HTTP request). In realtime mode the caller passes as many
// as it wants; in digest mode a whole batch of findings sends one message, so it passes 1.
//
// The bucket capacity is the channel's per-minute cap, refilled at a constant rate.
// ratePerMin<=0 means no rate limit and returns a finite but large-enough value, so one
// loop iteration is not dragged down by an unbounded backlog.
//
// The want cap is necessary: without it the bucket could only be drained entirely, yet the
// caller has its own per-tick cap, so tokens taken in excess are both unusable and vanish
// before the next refill — the accumulated burst capacity is never reachable, and even
// "this round has no pending deliveries" would be charged.
func (n *Notifier) takeTokens(channelID int64, ratePerMin, want int, now time.Time) int {
	if want <= 0 {
		return 0
	}
	if ratePerMin <= 0 {
		return min(want, notifyUnlimitedBurstPerTick)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// Refill by the real elapsed time, at a rate of ratePerMin/60 per second.
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// Add a tiny epsilon before truncating: the token count is accumulated in floating
	// point, and refilling in two halves can make 0.5 + 0.5 come out as 0.9999999999, which
	// a bare int() truncates to 0 — a bucket mathematically full yet yielding no token. 1e-9
	// is far smaller than one token and will not let a real shortfall slip by.
	take := min(int(b.tokens+1e-9), want)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled reads the master switch.
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL returns the external address used for deep links, with any trailing slash removed.
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval returns the digest interval, falling back to the default when invalid or unset.
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot parses the snapshot of the event a delivery corresponds to.
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf(trMsg(errDeliverySnapshotEmpty), dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf(trMsg(errDeliverySnapshotParse), dl.ID, err)
	}
	if snap.Kind == "" {
		// The event kind is authoritative from the event row; the copy in the snapshot may
		// have been written by an older version.
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
