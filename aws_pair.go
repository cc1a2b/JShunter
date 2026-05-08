package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AWS SigV4 verifier for sts:GetCallerIdentity.
//
// AWS credentials come in pairs (Access Key ID + Secret Access Key); a single
// AKID can't be verified alone — the signing process requires both. When
// JSHunter detects both in the same source, this verifier signs a minimal
// read-only POST to sts.amazonaws.com and reports back account/ARN.
//
// Region is fixed at us-east-1 because the global STS endpoint is
// regionalized as us-east-1; service is "sts". No SDK dependency.

const (
	awsService = "sts"
	awsRegion  = "us-east-1"
	awsHost    = "sts.amazonaws.com"
)

// AWSPair is a (AKID, SecretKey) tuple discovered in the same source.
type AWSPair struct {
	AccessKeyID     string
	SecretAccessKey string
	Source          string
	Line            int
	Column          int
}

// pairAWSCredentials walks the dedupe map and returns pairs that share a
// Source. The pairing is conservative: same source, both findings present.
// Cross-source pairing risks attaching the wrong secret to the wrong AKID.
func pairAWSCredentials() []AWSPair {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()

	bySource := map[string]struct {
		akids   []*Finding
		secrets []*Finding
	}{}
	for _, f := range findingsByHash {
		s := bySource[f.Source]
		switch f.RuleID {
		case "aws.access_key_id":
			s.akids = append(s.akids, f)
		case "aws.secret_access_key":
			s.secrets = append(s.secrets, f)
		}
		bySource[f.Source] = s
	}

	pairs := []AWSPair{}
	for src, s := range bySource {
		// Single AKID + single secret in the same source is the only case
		// we can pair with confidence. Multiple of either yield ambiguity;
		// skip those — operator can run --no-fp-filter and triage manually.
		if len(s.akids) == 1 && len(s.secrets) == 1 {
			a, sec := s.akids[0], s.secrets[0]
			pairs = append(pairs, AWSPair{
				AccessKeyID:     a.Value,
				SecretAccessKey: sec.Value,
				Source:          src,
				Line:            a.Line,
				Column:          a.Column,
			})
		}
	}
	return pairs
}

// verifyAWSPair calls sts:GetCallerIdentity with SigV4. Returns alive=true
// and the ARN of the caller on success, alive=false on any 4xx, error string
// on transport failure. Sanitizes any leaked secret from the error.
func verifyAWSPair(ctx context.Context, client *http.Client, p AWSPair) VerifyResult {
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	timeStr := now.Format("20060102T150405Z")

	bodyHash := sha256Hex([]byte(body))
	canonicalReq := strings.Join([]string{
		"POST",
		"/",
		"",
		"content-type:application/x-www-form-urlencoded; charset=utf-8",
		"host:" + awsHost,
		"x-amz-content-sha256:" + bodyHash,
		"x-amz-date:" + timeStr,
		"",
		"content-type;host;x-amz-content-sha256;x-amz-date",
		bodyHash,
	}, "\n")

	credScope := dateStr + "/" + awsRegion + "/" + awsService + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		timeStr,
		credScope,
		sha256Hex([]byte(canonicalReq)),
	}, "\n")

	signingKey := awsDeriveSigningKey(p.SecretAccessKey, dateStr, awsRegion, awsService)
	signature := hmacHex(signingKey, []byte(stringToSign))

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=%s",
		p.AccessKeyID, credScope, signature,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+awsHost+"/", strings.NewReader(body))
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	req.Host = awsHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", timeStr)
	req.Header.Set("X-Amz-Content-Sha256", bodyHash)
	req.Header.Set("Authorization", authHeader)

	host := req.URL.Host
	release := verifyHostLimiter.acquire(host)
	defer release()

	resp, err := client.Do(req)
	if err != nil {
		return VerifyResult{Error: sanitizeNetErr(err.Error())}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(&capReader{r: resp.Body, max: 32 * 1024})

	res := VerifyResult{Status: resp.StatusCode}
	if resp.StatusCode == http.StatusOK {
		res.Alive = true
		s := string(respBody)
		// STS returns XML with <Arn>arn:aws:iam::123456789012:user/Foo</Arn>.
		// We use substring extraction rather than a full XML decoder — the
		// expected response shape is stable and small.
		if i := strings.Index(s, "<Arn>"); i != -1 {
			j := strings.Index(s[i+5:], "</Arn>")
			if j != -1 {
				res.Account = s[i+5 : i+5+j]
			}
		}
		res.Note = "sts:GetCallerIdentity returned 200"
	} else {
		// Don't leak the response body — STS error replies can echo the
		// AKID. Sanitize aggressively.
		res.Note = fmt.Sprintf("sts returned %d", resp.StatusCode)
	}
	return res
}

// awsDeriveSigningKey computes the SigV4 signing key:
//
//	kDate    = HMAC("AWS4" + secret, dateStr)
//	kRegion  = HMAC(kDate, region)
//	kService = HMAC(kRegion, service)
//	kSigning = HMAC(kService, "aws4_request")
func awsDeriveSigningKey(secret, dateStr, region, service string) []byte {
	k := hmacBytes([]byte("AWS4"+secret), []byte(dateStr))
	k = hmacBytes(k, []byte(region))
	k = hmacBytes(k, []byte(service))
	return hmacBytes(k, []byte("aws4_request"))
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacBytes(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func hmacHex(key, msg []byte) string {
	return hex.EncodeToString(hmacBytes(key, msg))
}
