# edgeauth - Akamai Auth Token 2.0 Generator

A minimal, single-file Go implementation of Akamai "Auth Token 2.0" suitable for generating tokens from the command line.
It mirrors the signing rules used by the official SDKs.

## Usage

```
Usage:
  edgeauth [OPTIONS]

Application Options:
  -k, --key=                   Shared secret in hex [$EDGEAUTH_KEY]
  -d, --duration=              Token TTL (e.g. 300s, 15m, 1h).
      --acl=                   ACL string (e.g. /*). Use ! to join multiple patterns
      --url=                   Single URL path to authorize (e.g. /path/file)
      --ip=                    Bind token to client IP
      --id=                    Session ID
      --data=                  Arbitrary payload
      --salt=                  Additional salt (added only to the signed string)
      --start=                 Explicit start time (unix epoch). (default: 0)
      --exp=                   Explicit expiration time (unix epoch). Overrides --duration
      --algo=[sha256|sha1|md5] HMAC algorithm (default: sha256)
      --field-delim=           Field delimiter (default: ~)
      --acl-delim=             ACL delimiter for multiple ACL entries (default: !)
      --escape-early           URL-encode certain fields before signing (ip,id,data and url when URL mode)

Help Options:
  -h, --help                   Show this help message
```


## Examples

### 1) ACL mode, one hour, escape-early

```
$ edgeauth \
  --key 52a152a152a152a152a152a152a1 \
  --duration 1h \
  --acl "/*" \
  --escape-early
# -> st=1739674800~exp=1739678400~acl=/*~hmac=<hex>
```

### 2) URL mode (signs url=, does not emit it)

```
$ edgeauth \
  --key 52a152a152a152a152a152a152a1 \
  --duration 1h \
  --url "/secure/video.m3u8" \
  --escape-early
# -> st=...~exp=...~hmac=<hex>
```

### 3) Bind to client IP and fixed start time

```
$ edgeauth \
  --key 52a152a152a152a152a152a152a1 \
  --acl "/media/*" \
  --start 1760500000 \
  --duration 600s \
  --ip 203.0.113.4
$ -> ip=203.0.113.4~st=...~exp=...~acl=/media/*~hmac=<hex>
```
