package jshunter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verifier is the read-only liveness check for a discovered secret. Verifiers
// never POST, never mutate, never list resources beyond the smallest possible
// scope. Off by default — gated behind --verify — to keep recon legal and quiet.
type Verifier func(ctx context.Context, client *http.Client, value string) VerifyResult

// VerifyResult is the structured outcome of a single liveness probe.
type VerifyResult struct {
	Alive   bool   `json:"alive"`
	Status  int    `json:"status,omitempty"`
	Account string `json:"account,omitempty"`
	Note    string `json:"note,omitempty"`
	Error   string `json:"error,omitempty"`
}

// verifierRegistry maps rule_id -> liveness check.
var (
	verifierRegistry  = map[string]Verifier{}
	verifierRegOnce   sync.Once
	verifyHostLimiter = newHostLimiter(2, 250*time.Millisecond)
)

// registerVerifiers wires every rule that has a documented, read-only,
// no-cost endpoint we can use to confirm liveness without taking a destructive
// action. Per the brief: never auto-verify; always opt-in. Source citations
// for each endpoint are inline so a reviewer can audit at a glance.
func registerVerifiers() {
	verifierRegOnce.Do(func() {
		// Stripe — GET /v1/balance is the documented health-check endpoint:
		// https://docs.stripe.com/keys
		verifierRegistry["stripe.secret_key"] = stripeVerify
		verifierRegistry["stripe.restricted_key"] = stripeVerify

		// GitHub — GET /user with `Authorization: token <pat>`:
		// https://docs.github.com/en/rest/users/users
		verifierRegistry["github.pat_classic"] = githubVerify
		verifierRegistry["github.fine_grained_pat"] = githubVerify

		// OpenAI — GET /v1/models, no token cost:
		// https://platform.openai.com/docs/api-reference/models/list
		verifierRegistry["openai.legacy_key"] = openaiVerify
		verifierRegistry["openai.project_key"] = openaiVerify
		verifierRegistry["openai.svcacct_key"] = openaiVerify

		// Anthropic — GET /v1/models with x-api-key + anthropic-version:
		// https://platform.claude.com/docs/en/api/overview
		verifierRegistry["anthropic.api_key"] = anthropicVerify

		// Slack — GET auth.test, hundreds-rpm rate limit, returns ok+team:
		// https://docs.slack.dev/reference/methods/auth.test
		verifierRegistry["slack.user_or_bot_token"] = slackVerify
		verifierRegistry["slack.app_token"] = slackVerify

		// SendGrid — GET /v3/scopes returns the scopes the key has:
		// https://docs.sendgrid.com/api-reference/api-key-permissions
		verifierRegistry["sendgrid.api_key"] = sendgridVerify

		// Mailgun — GET /v3/domains with HTTP basic api:<key>:
		// https://documentation.mailgun.com/docs/mailgun/api-reference/openapi-final/tag/Domains/
		verifierRegistry["mailgun.api_key"] = mailgunVerify

		// HuggingFace — GET /api/whoami-v2 returns the user record:
		// https://huggingface.co/docs/api-inference/quicktour
		verifierRegistry["huggingface.token"] = huggingfaceVerify
	})
}

// hostLimiter bounds outbound calls per provider host so a verify pass over
// many findings doesn't trip rate limits and get the operator's IP banned.
type hostLimiter struct {
	mu      sync.Mutex
	tokens  map[string]chan struct{}
	per     int
	cooldown time.Duration
}

func newHostLimiter(per int, cooldown time.Duration) *hostLimiter {
	return &hostLimiter{
		tokens:   map[string]chan struct{}{},
		per:      per,
		cooldown: cooldown,
	}
}

func (h *hostLimiter) acquire(host string) func() {
	h.mu.Lock()
	ch, ok := h.tokens[host]
	if !ok {
		ch = make(chan struct{}, h.per)
		h.tokens[host] = ch
	}
	h.mu.Unlock()
	ch <- struct{}{}
	return func() {
		time.Sleep(h.cooldown)
		<-ch
	}
}

// runVerify dispatches `value` to the rule's verifier with a bounded timeout.
// Returns a redacted-friendly result; never returns the raw secret in errors.
func runVerify(ruleID, value string, client *http.Client, timeout time.Duration) VerifyResult {
	registerVerifiers()
	v, ok := verifierRegistry[ruleID]
	if !ok {
		return VerifyResult{Note: "no verifier registered for rule"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return v(ctx, client, value)
}

// doVerifyRequest is the shared HTTP path. It enforces the per-host limiter,
// reads at most 64 KiB of the response body (we only need status + small JSON),
// and translates any low-level error into a VerifyResult.Error string.
func doVerifyRequest(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, []byte, VerifyResult) {
	host := req.URL.Host
	release := verifyHostLimiter.acquire(host)
	defer release()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, nil, VerifyResult{Error: sanitizeNetErr(err.Error())}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(&capReader{r: resp.Body, max: 64 * 1024})
	return resp, body, VerifyResult{Status: resp.StatusCode}
}

// sanitizeNetErr ensures we never leak a secret value in an error message.
// Common transport errors include the URL with query/path; some tokens (e.g.,
// Slack legacy) can be passed as ?token=, so we redact aggressively.
func sanitizeNetErr(msg string) string {
	if i := strings.Index(msg, "token="); i != -1 {
		msg = msg[:i] + "token=***REDACTED***"
	}
	if i := strings.Index(msg, "Bearer "); i != -1 {
		msg = msg[:i] + "Bearer ***REDACTED***"
	}
	return msg
}

// capReader caps a stream at `max` bytes — verify endpoints return small JSON;
// a hostile or misconfigured proxy could otherwise stream arbitrary content.
type capReader struct {
	r   interface{ Read([]byte) (int, error) }
	max int64
	n   int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n >= c.max {
		return 0, fmt.Errorf("verify: response exceeded %d bytes", c.max)
	}
	if int64(len(p)) > c.max-c.n {
		p = p[:c.max-c.n]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// stripeVerify uses the documented lightweight `/v1/balance` endpoint.
// 200 → live, account info isn't returned by /v1/balance so we leave Account empty.
func stripeVerify(ctx context.Context, client *http.Client, value string) VerifyResult {
	req, err := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, _, res := doVerifyRequest(ctx, client, req)
	if resp == nil {
		return res
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		res.Alive = true
		res.Note = "stripe /v1/balance returned 200"
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		res.Note = "stripe rejected the key"
	default:
		res.Note = fmt.Sprintf("stripe returned %d", resp.StatusCode)
	}
	return res
}

// githubVerify hits /user. A successful response carries `login` which we
// surface as Account so the operator knows whose token they captured.
func githubVerify(ctx context.Context, client *http.Client, value string) VerifyResult {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "token "+value)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, body, res := doVerifyRequest(ctx, client, req)
	if resp == nil {
		return res
	}
	switch resp.StatusCode {
	case http.StatusOK:
		res.Alive = true
		var u struct {
			Login string `json:"login"`
		}
		_ = json.Unmarshal(body, &u)
		res.Account = u.Login
		res.Note = "github /user returned 200"
	case http.StatusUnauthorized:
		res.Note = "github rejected the token"
	default:
		res.Note = fmt.Sprintf("github returned %d", resp.StatusCode)
	}
	return res
}

// openaiVerify uses GET /v1/models. No token cost.
func openaiVerify(ctx context.Context, client *http.Client, value string) VerifyResult {
	req, err := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, _, res := doVerifyRequest(ctx, client, req)
	if resp == nil {
		return res
	}
	switch resp.StatusCode {
	case http.StatusOK:
		res.Alive = true
		res.Note = "openai /v1/models returned 200"
	case http.StatusUnauthorized:
		res.Note = "openai rejected the key"
	default:
		res.Note = fmt.Sprintf("openai returned %d", resp.StatusCode)
	}
	return res
}

// anthropicVerify uses x-api-key + anthropic-version on GET /v1/models.
func anthropicVerify(ctx context.Context, client *http.Client, value string) VerifyResult {
	req, err := http.NewRequest("GET", "https://api.anthropic.com/v1/models", nil)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.Header.Set("x-api-key", value)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, _, res := doVerifyRequest(ctx, client, req)
	if resp == nil {
		return res
	}
	switch resp.StatusCode {
	case http.StatusOK:
		res.Alive = true
		res.Note = "anthropic /v1/models returned 200"
	case http.StatusUnauthorized:
		res.Note = "anthropic rejected the key"
	default:
		res.Note = fmt.Sprintf("anthropic returned %d", resp.StatusCode)
	}
	return res
}

// slackVerify hits auth.test which returns ok=true plus team/user metadata.
// We surface team_id/user as Account for triage.
func slackVerify(ctx context.Context, client *http.Client, value string) VerifyResult {
	req, err := http.NewRequest("GET", "https://slack.com/api/auth.test", nil)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, body, res := doVerifyRequest(ctx, client, req)
	if resp == nil {
		return res
	}
	if resp.StatusCode != http.StatusOK {
		res.Note = fmt.Sprintf("slack returned %d", resp.StatusCode)
		return res
	}
	var s struct {
		OK     bool   `json:"ok"`
		Team   string `json:"team"`
		User   string `json:"user"`
		Error  string `json:"error"`
		TeamID string `json:"team_id"`
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		res.Note = "slack: cannot parse auth.test response"
		return res
	}
	if !s.OK {
		res.Note = "slack auth.test ok=false: " + s.Error
		return res
	}
	res.Alive = true
	res.Account = fmt.Sprintf("%s/%s (team=%s user=%s)", s.TeamID, s.UserID, s.Team, s.User)
	res.Note = "slack auth.test ok=true"
	return res
}

// sendgridVerify uses /v3/scopes to confirm the key works.
func sendgridVerify(ctx context.Context, client *http.Client, value string) VerifyResult {
	req, err := http.NewRequest("GET", "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, _, res := doVerifyRequest(ctx, client, req)
	if resp == nil {
		return res
	}
	switch resp.StatusCode {
	case http.StatusOK:
		res.Alive = true
		res.Note = "sendgrid /v3/scopes returned 200"
	case http.StatusUnauthorized, http.StatusForbidden:
		res.Note = "sendgrid rejected the key"
	default:
		res.Note = fmt.Sprintf("sendgrid returned %d", resp.StatusCode)
	}
	return res
}

// mailgunVerify uses HTTP Basic api:<key> against /v3/domains.
func mailgunVerify(ctx context.Context, client *http.Client, value string) VerifyResult {
	req, err := http.NewRequest("GET", "https://api.mailgun.net/v3/domains", nil)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.SetBasicAuth("api", value)
	resp, _, res := doVerifyRequest(ctx, client, req)
	if resp == nil {
		return res
	}
	switch resp.StatusCode {
	case http.StatusOK:
		res.Alive = true
		res.Note = "mailgun /v3/domains returned 200"
	case http.StatusUnauthorized:
		res.Note = "mailgun rejected the key"
	default:
		res.Note = fmt.Sprintf("mailgun returned %d", resp.StatusCode)
	}
	return res
}

// huggingfaceVerify uses /api/whoami-v2 which returns the account record.
func huggingfaceVerify(ctx context.Context, client *http.Client, value string) VerifyResult {
	req, err := http.NewRequest("GET", "https://huggingface.co/api/whoami-v2", nil)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, body, res := doVerifyRequest(ctx, client, req)
	if resp == nil {
		return res
	}
	if resp.StatusCode != http.StatusOK {
		res.Note = fmt.Sprintf("huggingface returned %d", resp.StatusCode)
		return res
	}
	var u struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	_ = json.Unmarshal(body, &u)
	res.Alive = true
	res.Account = fmt.Sprintf("%s (%s)", u.Name, u.Type)
	res.Note = "huggingface /api/whoami-v2 returned 200"
	return res
}
