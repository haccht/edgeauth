package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"net/url"
	"os"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
)

type options struct {
	Key         string `short:"k" long:"key" required:"true" description:"Shared secret in hex" env:"EDGEAUTH_KEY"`
	Duration    string `short:"d" long:"duration" description:"Token TTL (e.g. 300s, 15m, 1h)."`
	ACL         string `long:"acl" description:"ACL string (e.g. /*). Use ! to join multiple patterns"`
	URL         string `long:"url" description:"Single URL path to authorize (e.g. /path/file)"`
	IP          string `long:"ip" description:"Bind token to client IP"`
	SessionID   string `long:"id" description:"Session ID"`
	Payload     string `long:"data" description:"Arbitrary payload"`
	Salt        string `long:"salt" description:"Additional salt (added only to the signed string)"`
	StartTime   int64  `long:"start" default:"0" description:"Explicit start time (unix epoch)."`
	ExpireTime  int64  `long:"exp" description:"Explicit expiration time (unix epoch). Overrides --duration"`
	Algorithm   string `long:"algo" default:"sha256" choice:"sha256" choice:"sha1" choice:"md5" description:"HMAC algorithm"`
	FieldDelim  string `long:"field-delim" default:"~" description:"Field delimiter"`
	ACLDelim    string `long:"acl-delim" default:"!" description:"ACL delimiter for multiple ACL entries"`
	EscapeEarly bool   `long:"escape-early" description:"URL-encode certain fields before signing (ip,id,data and url when URL mode)"`
}

func run(opts options) error {
	if (opts.ACL == "" && opts.URL == "") || (opts.ACL != "" && opts.URL != "") {
		return fmt.Errorf("specify either --acl or --url exclusively")
	}

	keyBytes, err := hex.DecodeString(opts.Key)
	if err != nil || len(keyBytes) == 0 {
		return fmt.Errorf("invalid --key: must be hex")
	}

	var st int64
	var stPtr *int64
	switch {
	case opts.StartTime > 0:
		st = opts.StartTime
		stPtr = &st
	}

	var exp int64
	base := time.Now().UTC().Unix()
	switch {
	case opts.ExpireTime > 0:
		exp = opts.ExpireTime
	case opts.Duration != "":
		d, err := time.ParseDuration(opts.Duration)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid --duration: %v", err)
		}

		if stPtr != nil {
			base = *stPtr
		}
		exp = base + int64(d.Seconds())
	default:
		return fmt.Errorf("either --exp or --duration is required")
	}
	if exp <= 0 {
		return fmt.Errorf("--exp must be > 0")
	}
	if stPtr != nil && exp <= *stPtr {
		return fmt.Errorf("token already expired: exp <= st")
	}

	var tokenFields []string
	if opts.IP != "" {
		tokenFields = append(tokenFields, fmt.Sprintf("ip=%s", maybeEscape(opts.IP, opts.EscapeEarly)))
	}
	if stPtr != nil {
		tokenFields = append(tokenFields, fmt.Sprintf("st=%d", *stPtr))
	}
	tokenFields = append(tokenFields, fmt.Sprintf("exp=%d", exp))

	isURLMode := (opts.URL != "")
	if !isURLMode {
		tokenFields = append(tokenFields, fmt.Sprintf("acl=%s", opts.ACL))
	}
	if opts.SessionID != "" {
		tokenFields = append(tokenFields, fmt.Sprintf("id=%s", maybeEscape(opts.SessionID, opts.EscapeEarly)))
	}
	if opts.Payload != "" {
		tokenFields = append(tokenFields, fmt.Sprintf("data=%s", maybeEscape(opts.Payload, opts.EscapeEarly)))
	}

	hashFields := append([]string(nil), tokenFields...)
	if isURLMode {
		hashFields = append(hashFields, fmt.Sprintf("url=%s", maybeEscape(opts.URL, opts.EscapeEarly)))
	}
	if opts.Salt != "" {
		hashFields = append(hashFields, fmt.Sprintf("salt=%s", opts.Salt))
	}

	digestHex := computeHMAC(opts.Algorithm, keyBytes, strings.Join(hashFields, opts.FieldDelim))
	tokenFields = append(tokenFields, fmt.Sprintf("hmac=%s", digestHex))

	fmt.Println(strings.Join(tokenFields, opts.FieldDelim))
	return nil
}

func maybeEscape(s string, escape bool) string {
	if !escape {
		return s
	}
	return strings.ToLower(url.QueryEscape(s))
}

func computeHMAC(a string, key []byte, data string) string {
	var newHash func() hash.Hash
	switch a {
	case "sha256":
		newHash = sha256.New
	case "sha1":
		newHash = sha1.New
	case "md5":
		newHash = md5.New
	default:
		newHash = sha256.New
	}
	mac := hmac.New(newHash, key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func main() {
	var opts options
	if _, err := flags.Parse(&opts); err != nil {
		os.Exit(1)
	}

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err)
		os.Exit(2)
	}
}
