package trace

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// This file defends signature matching against the string-obfuscation tricks
// supply-chain malware uses to dodge substring detection. SCBoX is a dynamic
// sandbox, so values assembled at runtime (require(['child','_process'].join('_')),
// globalThis['ev'+'al'], String.fromCharCode(...)) are already RESOLVED when they
// reach our require/eval/spawn hooks - those paths are caught by execution. But
// when we scan a recovered STATIC blob (a decrypted/decoded payload that has not
// been executed, e.g. because it hides behind a magic-arg gate), the obfuscation
// is still intact. deobfuscateViews expands the common encodings so a token like
// "child_process" or "sh -c" becomes visible regardless of how it was split.

var (
	// 'a' + 'b'  /  "a"+"b"  /  `a`+`b`  - the seam of split-string concatenation.
	concatBoundaryRe = regexp.MustCompile("['\"`]\\s*\\+\\s*['\"`]")
	// Everything quote/plus/whitespace - a lossy fully-collapsed view.
	stripJunkRe = regexp.MustCompile("['\"`+]|\\s+")
	// String.fromCharCode(115,104,0x2d) and the .apply/spread variants.
	fromCharCodeRe = regexp.MustCompile(`(?i)(?:String\.)?fromCharCode(?:\.apply\([^,]*,\s*\[?|\()([0-9a-fxX,\s]+)\]?\s*\)`)
	// \xHH byte escapes and \uHHHH / \u{...} unicode escapes.
	hexEscRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	uniEscRe = regexp.MustCompile(`\\u\{?([0-9a-fA-F]{1,6})\}?`)
	// ['c','h','i','l','d'].join('')  →  "child"
	arrayJoinRe = regexp.MustCompile(`\[([^\[\]]*?)\]\s*\.\s*join\s*\([^)]*\)`)
	stringLitRe = regexp.MustCompile("['\"`]([^'\"`]*)['\"`]")
	// 'ssecorp'.split('').reverse().join('')  →  "process"
	reverseRe = regexp.MustCompile(`['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]\s*\.\s*split\s*\([^)]*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\([^)]*\)`)
	// A run of base64 long enough to carry a command (>=16 chars), and a run of
	// hex bytes (>=8 bytes). These surface payloads smuggled as an encoded blob -
	// `echo <b64> | base64 -d | sh`, `eval(Buffer.from('<hex>','hex'))`, a hex/b64
	// command literal - that the plain string views can't read.
	b64BlobRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexBlobRe = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}){8,}`)
	// A run of base32 (RFC 4648 alphabet, upper-case A-Z + 2-7) long enough to
	// carry a command, with optional `=` padding - another encode-a-payload layer.
	base32BlobRe = regexp.MustCompile(`[A-Z2-7]{16,}={0,6}`)
	// A run of base58 (Bitcoin alphabet - no 0/O/I/l) long enough to carry a
	// command. Base58 commonly wraps keys/addresses but also smuggled blobs.
	base58BlobRe = regexp.MustCompile(`[1-9A-HJ-NP-Za-km-z]{16,}`)
)

// base58Alphabet is the Bitcoin base58 alphabet (no 0, O, I, l).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// decodeBase58 decodes a Bitcoin-alphabet base58 string to bytes. Input length is
// capped (~1024) to bound the big.Int cost; over-long or invalid input returns
// (nil,false). Leading '1's map to leading zero bytes, matching base58 semantics.
func decodeBase58(s string) ([]byte, bool) {
	if s == "" || len(s) > 1024 {
		return nil, false
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	radix := big.NewInt(58)
	num := new(big.Int)
	tmp := new(big.Int)
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(base58Alphabet, s[i])
		if idx < 0 {
			return nil, false
		}
		num.Mul(num, radix)
		num.Add(num, tmp.SetInt64(int64(idx)))
	}
	dec := num.Bytes()
	out := make([]byte, zeros+len(dec))
	copy(out[zeros:], dec)
	return out, true
}

// joinStringConcat collapses adjacent concatenated string literals so a payload
// written as `'s'+'h'+' '+'-'+'c'` reads as `'sh -c'`.
func joinStringConcat(s string) string { return concatBoundaryRe.ReplaceAllString(s, "") }

// stripQuoteJunk removes quotes, `+`, and whitespace - a last-resort collapsed
// view that reveals tokens split with arbitrary junk between literals. Lossy, so
// it is only one of several scanned views.
func stripQuoteJunk(s string) string { return stripJunkRe.ReplaceAllString(s, "") }

// decodeCharCodes turns String.fromCharCode(115,104,...) into its characters.
func decodeCharCodes(s string) string {
	return fromCharCodeRe.ReplaceAllStringFunc(s, func(m string) string {
		inside := fromCharCodeRe.FindStringSubmatch(m)[1]
		var b strings.Builder
		for _, part := range strings.Split(inside, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			var n int64
			var err error
			if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
				n, err = strconv.ParseInt(part[2:], 16, 32)
			} else {
				n, err = strconv.ParseInt(part, 10, 32)
			}
			if err == nil && n > 0 && n < 0x110000 {
				b.WriteRune(rune(n))
			}
		}
		return b.String()
	})
}

// decodeEscapes resolves \xHH and \uHHHH / \u{...} escapes to their characters.
func decodeEscapes(s string) string {
	s = hexEscRe.ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseInt(m[2:], 16, 32)
		return string(rune(n))
	})
	s = uniEscRe.ReplaceAllStringFunc(s, func(m string) string {
		h := uniEscRe.FindStringSubmatch(m)[1]
		n, err := strconv.ParseInt(h, 16, 32)
		if err != nil || n >= 0x110000 {
			return ""
		}
		return string(rune(n))
	})
	return s
}

// decodeArrayJoin turns ['c','h','i','l','d'].join(”) into "child" (separator is
// ignored - joining the literals contiguously is enough to surface the token).
func decodeArrayJoin(s string) string {
	return arrayJoinRe.ReplaceAllStringFunc(s, func(m string) string {
		inside := arrayJoinRe.FindStringSubmatch(m)[1]
		var b strings.Builder
		for _, lit := range stringLitRe.FindAllStringSubmatch(inside, -1) {
			b.WriteString(lit[1])
		}
		if b.Len() == 0 {
			return m
		}
		return b.String()
	})
}

// decodeReverse resolves 'ssecorp'.split(”).reverse().join(”) to "process".
func decodeReverse(s string) string {
	return reverseRe.ReplaceAllStringFunc(s, func(m string) string {
		lit := reverseRe.FindStringSubmatch(m)[1]
		r := []rune(lit)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r)
	})
}

// mostlyPrintable reports whether b is dominated by printable ASCII (text/script
// content), used to discard the binary garbage that decoding a non-encoded blob
// produces - only a decode that yields plausible text is worth re-scanning.
func mostlyPrintable(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	ok := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			ok++
		}
	}
	return float64(ok)/float64(len(b)) >= 0.85
}

// Bounds for the encoded-blob recovery below. Decoding is recursive - a blob can
// wrap a gzip stream or another encoding (base64-of-base64) - so every limit is a
// hard stop against a decompression bomb or pathological nesting fed by untrusted
// input. deobfuscateViews runs per IOC-set member at verdict time (scanSets),
// outside the goja budget, so unbounded work here is a DoS (cf. the IOC-set caps).
const (
	maxDecodeDepth   = 4       // layers of nested encoding/compression to peel
	maxInflateBytes  = 1 << 20 // cap on a single gunzip/inflate output
	maxRecoveredText = 1 << 20 // cap on total recovered text per top-level call
)

// tryInflate detects a gzip (1f 8b) or zlib (78 ..) stream and returns its
// decompressed bytes, output-capped against a zip bomb. A truncated stream still
// yields the bytes read so far - enough to surface a smuggled command. Raw
// (headerless) DEFLATE is intentionally not probed: it has no magic, so detecting
// it would false-decode arbitrary bytes.
func tryInflate(b []byte) ([]byte, bool) {
	var zr io.ReadCloser
	switch {
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false
		}
		zr = r
	case len(b) >= 2 && b[0] == 0x78:
		r, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false
		}
		zr = r
	default:
		return nil, false
	}
	defer zr.Close()
	out, _ := io.ReadAll(io.LimitReader(zr, maxInflateBytes))
	return out, len(out) > 0
}

// blobRecover accumulates recovered plaintext from nested encoded/compressed
// blobs, bounded by maxRecoveredText.
type blobRecover struct{ b strings.Builder }

func (r *blobRecover) full() bool { return r.b.Len() >= maxRecoveredText }

// emit inflates a recovered blob if it is a gzip/zlib stream, records it when it
// is plausible text, and peels one further layer of nesting from recovered text.
func (r *blobRecover) emit(dec []byte, depth int) {
	if r.full() || len(dec) < 4 {
		return
	}
	if inflated, ok := tryInflate(dec); ok {
		dec = inflated
	}
	if !mostlyPrintable(dec) {
		return
	}
	r.b.WriteByte(' ')
	r.b.Write(dec)
	r.peel(string(dec), depth+1) // base64-of-base64 / gzip-then-base64 chains
}

// peel decodes the base64/hex/base32/base58 runs in s and feeds each to emit,
// recursing into recovered text so a multi-layer-packed payload (gzip then
// base64, or base64 then base64) is unwrapped to a scannable form. Depth and
// size are bounded (see consts) so untrusted input cannot drive unbounded work.
func (r *blobRecover) peel(s string, depth int) {
	if depth >= maxDecodeDepth || r.full() {
		return
	}
	for _, m := range b64BlobRe.FindAllString(s, -1) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if dec, err := enc.DecodeString(m); err == nil && len(dec) >= 4 {
				r.emit(dec, depth)
				break
			}
		}
	}
	for _, m := range hexBlobRe.FindAllString(s, -1) {
		if len(m)%2 != 0 {
			m = m[:len(m)-1]
		}
		if dec, err := hex.DecodeString(m); err == nil {
			r.emit(dec, depth)
		}
	}
	// base32 (RFC 4648). The regex already constrains to the upper-case alphabet,
	// but upper-case defensively in case a future widening lets lower-case through.
	for _, m := range base32BlobRe.FindAllString(s, -1) {
		if dec, err := base32.StdEncoding.DecodeString(strings.ToUpper(m)); err == nil && len(dec) >= 4 {
			r.emit(dec, depth)
		}
	}
	// base58 (Bitcoin alphabet). decodeBase58 caps input length to bound cost.
	for _, m := range base58BlobRe.FindAllString(s, -1) {
		if dec, ok := decodeBase58(m); ok && len(dec) >= 4 {
			r.emit(dec, depth)
		}
	}
}

// decodeDataBlobs finds base64/hex/base32/base58 runs in s, decodes them
// (recursively, peeling gzip/zlib compression and nested encodings), and returns
// the recovered text that decodes to plausible content. This peels the
// encode/compress-a-command layers malware wraps a payload in to dodge substring
// scans, so a downloader/reverse-shell/dropper hidden inside `Buffer.from('<hex>',
// 'hex')`, `gunzip(Buffer.from(b64))`, or a base64-of-base64 chain becomes visible
// to every signature. Operates on the original-case string (base64 is
// case-sensitive) before the final lowercase.
func decodeDataBlobs(s string) string {
	var r blobRecover
	r.peel(s, 0)
	return r.b.String()
}

// rot13 applies the ROT13 letter substitution to ASCII a-z/A-Z (other bytes
// pass through). A token obfuscated as `puvyq_cebprff` decodes to `child_process`,
// becoming scannable. Cheap and self-inverse, with near-zero false-positive risk.
func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// deobfuscateViews returns one lowercased string combining the raw text with
// several decoded views, so a signature scan over the result catches a token no
// matter which obfuscation split or encoded it. Decoders are also composed (e.g.
// concat-join then char-code decode) to peel one layer of nesting.
func deobfuscateViews(s string) string {
	joined := joinStringConcat(s)
	views := []string{
		s,
		joined,
		decodeCharCodes(s),
		decodeCharCodes(joined),
		decodeEscapes(s),
		decodeEscapes(joined),
		decodeArrayJoin(s),
		decodeReverse(s),
		stripQuoteJunk(s),
		// fully-peeled best effort: join, then resolve escapes and char codes.
		decodeEscapes(decodeCharCodes(joined)),
		// base64/hex/base32/base58 blobs decoded to text (a command smuggled as an
		// encoded blob).
		decodeDataBlobs(s),
		// ROT13-obfuscated tokens (`puvyq_cebprff` -> `child_process`).
		rot13(s),
	}
	return strings.ToLower(strings.Join(views, " \n "))
}
