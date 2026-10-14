package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// emailDialTimeout / emailSessionTimeout bound connection establishment and the entire SMTP session respectively.
// net/smtp itself has no timeout mechanism; without these two, a stuck peer would leave the
// delivery goroutine hung there forever — and since the dispatcher processes serially in a single goroutine,
// that amounts to the whole notification system grinding to a halt.
const (
	emailDialTimeout    = 10 * time.Second
	emailSessionTimeout = 45 * time.Second
)

// emailChannel implements SMTP email delivery.
type emailChannel struct{}

func (emailChannel) Kind() string { return KindEmail }

// Email has no platform rate limit, but it should not be used to spam; a generous default is given.
func (emailChannel) DefaultRatePerMin() int { return 60 }

// Only the password is masked. The SMTP host, account, and recipients are not secrets, and masking them would only make editing cumbersome.
func (emailChannel) SecretKeys() []string { return []string{"password"} }

// host/port decide which server the password is handed to; tls decides whether the transport is encrypted. A change to any of the three
// requires re-declaring the password — which also makes "turning off TLS" require explicitly carrying the credential, rather than a casual edit.
func (emailChannel) DestinationKeys() []string { return []string{"host", "port", "tls"} }

func (emailChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "host") == "" {
		return errors.New("SMTP 서버 주소가 없습니다")
	}
	port := cfgInt(cfg, "port")
	if port <= 0 || port > 65535 {
		return errors.New("SMTP 포트가 올바르지 않습니다 (1-65535 범위여야 합니다)")
	}
	if cfgString(cfg, "from") == "" {
		return errors.New("발신자 주소가 없습니다")
	}
	if len(cfgStrings(cfg, "to")) == 0 {
		return errors.New("수신자 주소가 최소 하나 필요합니다")
	}
	return nil
}

func (c emailChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	host := cfgString(cfg, "host")
	port := cfgInt(cfg, "port")
	from := cfgString(cfg, "from")
	to := cfgStrings(cfg, "to")
	username := cfgString(cfg, "username")
	password := cfgString(cfg, "password")
	implicitTLS := cfgBool(cfg, "tls")

	msg, err := buildEmailMessage(from, to, m)
	if err != nil {
		return 0, Permanent(err)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := emailDial(ctx, addr, host, implicitTLS)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	// STARTTLS: upgrade if the peer supports it. Credentials cannot be sent over a plaintext session (see the auth note below).
	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return 0, fmt.Errorf("STARTTLS 실패: %w", err)
			}
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			// smtp.PlainAuth refuses to send credentials over an unencrypted connection (unless the target is localhost).
			// This is the **correct** security behavior, must not be bypassed, but the reason needs to be spelled out clearly —
			// otherwise the user would just see "unencrypted connection" without knowing what to do.
			if strings.Contains(err.Error(), "unencrypted connection") {
				return 0, Permanent(fmt.Errorf("자격 증명 전송을 거부했습니다: 연결이 암호화되지 않았습니다. TLS 를 켜거나, 465 포트(암시적 TLS)를 사용하거나, 「TLS 사용」을 체크하세요 (%w)", err))
			}
			return 0, Permanent(fmt.Errorf("SMTP 인증 실패: %w", err))
		}
	}
	if err := client.Mail(from); err != nil {
		return 0, smtpStageError(fmt.Sprintf("발신자 %s 주소가 거부되었습니다", from), err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return 0, smtpStageError(fmt.Sprintf("수신자 %s 주소가 거부되었습니다", rcpt), err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return 0, fmt.Errorf("SMTP DATA 실패: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return 0, fmt.Errorf("메일 본문 쓰기 실패: %w", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("메일 제출 실패: %w", err)
	}
	// A Quit failure does not change the fact that "the email was accepted by the server", so its error is ignored.
	_ = client.Quit()
	// Email has no length truncation (the entire HTML body is sent), so the whole batch counts as delivered.
	return len(m.Items), nil
}

// emailDial establishes the SMTP connection.
//
// implicitTLS=true uses the 465-style "TLS on connect" approach; false uses 25/587, connecting in plaintext and then
// STARTTLS. The two cannot be mixed: sending a plaintext greeting to port 465 gets disconnected outright.
//
// The session deadline is set **at connection time** (not patched in afterwards), because net/smtp's Client hides the underlying
// connection in an unexported field that outsiders cannot reach; once the connection is handed over, only the pre-set deadline
// can backstop it. This also incidentally covers blocking during the handshake phase.
// Attaching blockInternalDial to Control shares the same guard as the HTTP-family channels. Without it, SMTP
// would be the gap in the whole SSRF protection: a host of 169.254.169.254 or 127.0.0.1 could connect directly,
// and when smtp.NewClient's handshake fails it wraps the peer's returned line into the error, which via last_error
// is echoed by the delivery-history endpoint, forming a semi-blind read primitive; the timing difference of "connection refused vs timeout" can also
// be used to probe ports. The dial stage is the final enforcement point, and also covers DNS rebinding.
func emailDial(ctx context.Context, addr, host string, implicitTLS bool) (*smtp.Client, error) {
	d := &net.Dialer{Timeout: emailDialTimeout, Control: blockInternalDial}
	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("SMTP 서버 연결 실패: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(emailSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP 핸드셰이크 실패: %w", err)
	}
	return client, nil
}

// smtpStageError classifies a stage failure as "retryable" or "permanent failure" by the SMTP reply code.
//
// Why the distinction is necessary: SMTP's 4xx and 5xx have entirely different semantics —
//   - 4xx (450 greylisting, 451 local error, 452 insufficient storage) is a **temporary** rejection,
//     where the proper practice is to retry later; greylisting especially is hit on almost every first delivery.
//   - 5xx (550 user does not exist, 553 illegal address) is a permanent rejection where retrying is meaningless.
//
// If everything were judged a permanent failure, a greylisting-enabled mail server would make **every single** push fall into
// failed after its first attempt — yet this kind of failure is exactly where automatic retry should shine.
// The reply code is taken from the first three digits of the error text; when no code can be obtained it is treated as retryable (better to try once more
// than to condemn a possibly transient fault just because parsing failed).
func smtpStageError(what string, err error) error {
	code := smtpReplyCode(err.Error())
	if code >= 500 && code < 600 {
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	return fmt.Errorf("%s: %w", what, err)
}

// smtpReplyCode takes the leading three-digit reply code from the SMTP error text, returning 0 if none can be obtained.
// net/smtp does not export an error-code field, so it can only be taken from the text; the format is "450 4.7.1 ...".
func smtpReplyCode(text string) int {
	if len(text) < 3 {
		return 0
	}
	n, err := strconv.Atoi(text[:3])
	if err != nil {
		return 0
	}
	return n
}

// buildEmailMessage assembles a complete RFC 5322 email.
//
// The body is base64-encoded for two reasons: first, SMTP mandates a single line not exceeding 1000 bytes, while an HTML
// body (especially a digest email) easily contains overly long lines; second, base64 naturally never produces a line
// starting with ".", sparing the trouble of SMTP dot-escaping.
func buildEmailMessage(from string, to []string, m Message) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	// A non-ASCII subject must be RFC 2047-encoded, otherwise it would display as garbage in the client.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", htmlTitle(m)))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	// Email has no hard length limit, so the body is not truncated.
	b.WriteString("\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(htmlBody(m, 0)))
	// base64 is wrapped at 76 characters, per RFC 2045.
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return b.String(), nil
}
