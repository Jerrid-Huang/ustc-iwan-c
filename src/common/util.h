#ifndef IWAN_UTIL_H
#define IWAN_UTIL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* R37-F3 (R3-M5): format checking for our own printf-like wrappers.
 * Without this attribute the compiler did not check any of the 250+
 * log/error call sites at all, which is how a %zu in a log call could
 * pass every gate but the two places that went through libc's fprintf
 * (that exact split is R3-H1: auth.c:416 broke the mingw build while
 * oidc_config.c's err_printf was silently unchecked).
 *
 * The archetype is the plain `printf`, i.e. "whatever the target libc's
 * printf is" — exactly the contract of these wrappers, which all forward
 * `fmt` to vfprintf/vsnprintf. Measured on this tree:
 *   - gcc/Linux and clang/Linux: %zu is valid (gnu semantics), other
 *     mismatches are still rejected;
 *   - MinGW gcc, under the win64 build flags: the same attribute yields
 *     byte-identical diagnostics to a direct libc fprintf call — both
 *     reject %zu with "unknown conversion type character 'z' in format"
 *     — so a %zu in a log call is caught in win-cross exactly the way
 *     R3-H1's auth.c:416 direct fprintf was, instead of shipping a
 *     broken deliverable.
 * The named archetypes are NOT portable, measured on this tree:
 *   gnu_printf — clang: "'format' attribute argument not supported"
 *                (with -Werror that breaks the CI clang leg);
 *   ms_printf  — gcc/Linux: "unrecognized format function type", and
 *                clang rejects it too;
 *   gnu_printf — MinGW gcc accepts it but treats %zu as valid, which
 *                would silently defeat the Windows check.
 * NOTE: __MINGW_PRINTF_FORMAT cannot be used here either — it is not
 * guaranteed to be defined at this point of the include graph (util.h
 * pulls in no libc stdio header), and util.h is included very early
 * everywhere. */
#if defined(__GNUC__)
#  define IWAN_PRINTF_FMT printf
#  define IWAN_PRINTF_LIKE(a, b) __attribute__((format(IWAN_PRINTF_FMT, a, b)))
#else
#  define IWAN_PRINTF_LIKE(a, b)   /* non-GCC: no checking */
#endif

#ifdef IWAN_DEBUG_STRIP
#define log_debug(...) ((void)0)
static inline bool debug_enabled(void) { return false; }
#else
bool debug_enabled(void);
#endif

/* R37 R5 (R3-L17 + M5 remainder): one shared spelling rule for the
 * boolean feature env vars (IWAN_DEBUG, IWAN_PROFILE,
 * IWAN_WIN_THREAD_PIN, IWAN_ELEVATED_RELAUNCH). Contract:
 *   - unset, or the empty string        -> dflt
 *   - case-insensitive {0,false,no,off} -> false
 *   - any other non-empty value         -> true
 * Both "loose" choices are load-bearing, do not tighten them:
 *   - unknown values stay ON: operators use IWAN_DEBUG=yes and
 *     IWAN_PROFILE=2, and a fail-closed positive list would silently
 *     switch those off. This is also why the security opt-outs
 *     (IWAN_ALLOW_INSECURE_USERS, IWAN_SOCKS_ALLOW_LOOPBACK,
 *     IWAN_RELAY_ALLOW_LOOPBACK) must keep their own exact-token rule
 *     instead of calling this helper;
 *   - no whitespace trimming: " 0" has always been ON in
 *     debug_enabled(), and trimming would silently stop a running debug
 *     session. "0 " is likewise NOT an off spelling.
 * Per-site delta vs the code this replaced (narrowing only, i.e. a
 * value that used to be OFF never becomes ON, with one exception):
 *   - debug_enabled(): off list {0,false,off} was case-sensitive and had
 *     no "no" -> "no"/"No"/"FALSE"/"OFF" turn off (the R3-L17 fix);
 *   - prof_init(): same list, was case-sensitive -> case variants turn
 *     off; "no" was already handled there;
 *   - IWAN_ELEVATED_RELAUNCH (port.c, oidc_util.c): was existence-only,
 *     so ""/0/false/no/off were ON -> now off;
 *   - the IWAN_WIN_THREAD_PIN sites (tun_win.c:681, proxy.c:619) used
 *     `pin && pin[0] != '0'`: a ONE-BYTE test, so ""/false/no/off (and
 *     their case variants) were ON -> now off, while the whole CLASS of
 *     leading-'0' values that is not exactly the one-byte "0" — "0 ",
 *     "00", "0x", "0abc", "0\n" ... i.e. every string whose first byte is
 *     '0' except "0" itself — was OFF and is now ON. The predicate is
 *     util.c:54-64 (exact, case-insensitive 0/false/no/off, no trimming),
 *     so trailing garbage is not an off spelling. Documented exception; it
 *     affects the experimental Windows affinity hint only.
 * No internal cache: exactly one getenv() per call, so a caller that
 * needs a cached or atomic answer keeps its own (debug_enabled() does).
 * Do NOT re-express dbg_env() (see its looser documented contract
 * above) or the exact-"1" security opt-outs with this helper. */
bool env_bool(const char *name, bool dflt);

/* ---------------- R37 R7 WG-E: one env parser, one env doc table ----------
 *
 * R6-I4 root cause: the boolean/numeric env rules were re-expressed at 13
 * boolean and 8 numeric call sites, and the documented matrix existed in
 * four copies (three --help footers + README.md) that drifted twice inside
 * one release. This block is the single source for the PARSING half:
 *   - parsing: env_bool_value()/env_bool_ex() are the only boolean
 *     predicates, env_scan_u64()/env_scan_i64() the env layer's only
 *     decimal scanners (parse_uint, env_ms_range, env_u64 all delegate to
 *     them), and a site's env_bool_kind names its rule, so a call site can
 *     no longer invent a sixth spelling silently.
 *
 * NOT LANDED — still the lower half of judgement criterion ④ (R38 P2-9):
 * the DOCUMENTATION half. There is no env-documentation table and none of
 * the four env-doc helpers (find / emit / bool-rule / also-read) in this
 * tree, and the "R7-WG-E checker" that was supposed to compare README.md
 * against that table does not exist either. The env matrix is still four
 * hand-maintained copies (the --help footers of src/iwan_server.c,
 * src/iwan_client.c and src/oidc/oidc_cli.c, plus README.md's three
 * tables). R38 deleted the declarations that described this as landed;
 * re-introduce table + emitter + checker together if that consolidation is
 * wanted.
 *
 * The boolean rules in use across the tree (six spellings, one per live
 * site family). Naming one of these is mandatory: a new
 * `strcmp(v, "0") != 0` is a bug.
 *
 * dflt is NOT uniform across the kinds — the env_bool_value() switch in
 * util.c is the authority, and this is what it does:
 *   LOOSE / CS / CS_NO -> dflt is the "unset" answer AND the "set but
 *                         empty" answer (the empty string is treated
 *                         exactly like unset);
 *   PRESENT            -> dflt is the "unset" answer only; a set-but-empty
 *                         value is ON;
 *   EXACT1 / POSITIVE  -> dflt is IGNORED entirely (fail-closed
 *                         allow-lists: unset is false even if dflt is
 *                         true);
 *   ENV_KIND_NUM       -> not a boolean; env_bool_value() returns dflt for
 *                         it, so never call it as one — use env_u64() /
 *                         env_ms_range() instead. */
typedef enum {
    ENV_BOOL_LOOSE = 0,  /* env_bool(): unset AND set-but-empty take dflt;
                            exact 0/false/no/off are OFF, case-INSENSITIVE;
                            every other non-empty value is ON (uses dflt) */
    ENV_BOOL_CS,         /* dbg_env() ONLY (IWAN_DEBUG/IWAN_RXDBG/
                            IWAN_FLOWDBG): the off list is {0,false,off},
                            case-SENSITIVE, and it has NO "no"/"No"
                            (documented exception, kept value-for-value);
                            unset and set-but-empty take dflt. Do NOT
                            migrate IWAN_SRV_TUN_SINGLE here — see
                            ENV_BOOL_CS_NO below. */
    ENV_BOOL_PRESENT,    /* IWAN_PUMP_PROF: SET AT ALL is ON ("" included);
                            only "unset" takes dflt (unlike LOOSE/CS/CS_NO,
                            a set-but-empty value here is ON) */
    ENV_BOOL_EXACT1,     /* the *_ALLOW_LOOPBACK SSRF opt-outs: only the
                            exact string "1" is ON; ignores dflt entirely
                            (unset is false even when dflt is true) */
    ENV_BOOL_POSITIVE,   /* IWAN_ALLOW_INSECURE_USERS: 1/true/yes/on,
                            case-insensitive; ignores dflt entirely (unset
                            is false even when dflt is true) */
    ENV_BOOL_CS_NO,      /* IWAN_SRV_TUN_SINGLE (server.c:345, via
                            env_bool_value(ENV_BOOL_CS_NO, ..., false)):
                            the LOOSE token set {0,false,no,off} but
                            case-SENSITIVE, i.e. a sixth spelling. It exists
                            because "=0" used to mean ON under an
                            existence-only parse. Do NOT "simplify" this
                            site to ENV_BOOL_CS: that would silently turn
                            "=no" from OFF into ON. Unset and set-but-empty
                            take dflt, matching the `e && *e` short-circuit
                            of the inline chain it replaced (value-for-value
                            equivalence was checked over 15 cells before the
                            swap — see .cc_tmp/r38/fixes/notes-srv-h1.md). */
    ENV_KIND_NUM,        /* not a boolean: strict decimal, see env_u64() */
} env_bool_kind;

/* pure predicate: v == NULL means "unset". No getenv(), no cache, so the
 * matrix checker can drive every value verbatim. */
bool env_bool_value(env_bool_kind kind, const char *v, bool dflt);
/* one getenv() + env_bool_value(). env_bool() is
 * env_bool_ex(name, ENV_BOOL_LOOSE, dflt). */
bool env_bool_ex(const char *name, env_bool_kind kind, bool dflt);

/* The one strict decimal scanner. The WHOLE string must be [0-9]+ (the
 * signed variant additionally accepts one leading '-'); leading/trailing
 * whitespace, '+', trailing garbage, empty and overflow are all rejected,
 * and leading zeros are legal ("007" -> 7). Return codes are parse_uint's
 * three-state contract: env_scan_u64 returns PARSE_UINT_OK/BAD/RANGE,
 * env_scan_i64 returns 0/-1. parse_uint() itself is this function. */
int env_scan_u64(const char *s, uint64_t max, uint64_t *out);
int env_scan_i64(const char *s, long long *out);

/* env_ms_range's unsigned sibling: unset/empty -> defval silently; a value
 * that env_scan_u64 rejects or that falls outside [min,max] -> warning +
 * defval. allow_zero lets an explicit 0 (the documented "disabled"
 * sentinel) pass through unvalidated. */
uint64_t env_u64(const char *name, uint64_t defval, uint64_t min, uint64_t max,
                 int allow_zero, const char *range_desc);

/* ---------------- the documented env matrix — NOT LANDED (R38 P2-9) ------
 *
 * R37 R7 WG-E's documentation half (an env-documentation table plus the
 * four env-doc helpers: find / emit / bool-rule / also-read) was never
 * implemented: the declarations that used to sit here had no definition
 * and no caller anywhere in src/ or tests/ (grep proof in
 * .cc_tmp/r38/fixes/notes-env-core.md), and the "R7-WG-E checker" they
 * referred to does not exist either. R38 deleted them rather than shipping
 * a header that describes a mechanism as landed when it is not; the TODO is
 * recorded in the block comment above. See iwan_server.c/iwan_client.c/
 * oidc_cli.c's --help footers and README.md for the four hand-maintained
 * copies that a future table would replace. */

/* reset PATH to a safe default and clear loader-injection vars; call in
 * the child before exec of helper binaries (root daemon hardening) */
void exec_sanitize(void);
/* run `ip` with argv (NULL-terminated, excluding argv[0]="ip"). Returns exit==0. */
bool ip_run(char *const args[]);
/* capture stdout of a command (NULL-terminated argv, excluding argv[0]).
 * Returns malloc'd string or NULL. NOTE: NULL is returned both when the
 * command fails AND when it succeeds with empty output (callers so far
 * treat the two identically — verify before relying on the distinction). */
char *cmd_capture(char *const args[]);

/* allocation failure is fatal: growable buffers and string helpers have no
 * error path, so report and abort instead of dereferencing NULL */
_Noreturn void oom_abort(void);

void log_info(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);   /* -> stdout */
void log_err(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);    /* -> stderr */
#ifndef IWAN_DEBUG_STRIP
void log_debug(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);  /* -> stderr if IWAN_DEBUG */
#endif
/* raw stderr printf (no newline, no flush): the shared implementation
 * behind the eprintf/oidc_eprintf helpers (log_err appends a newline
 * instead) */
void err_printf(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);

/* diagnostic env flags (IWAN_RXDBG / IWAN_FLOWDBG): parsed once per name
 * and cached; any value other than the exact, case-SENSITIVE 0/false/off
 * enables — there is deliberately no "no"/"No" spelling here (that is the
 * ENV_BOOL_CS rule above: a documented exception, not a bug to "fix" in
 * place, because dbg_env()'s looser contract long predates the helper) */
bool dbg_env(const char *name);

/* parse a millisecond duration from env var `name`; see util.c. Returns
 * defval when unset/empty/unparseable/out-of-range (with a warning);
 * allow_zero lets an explicit 0 (the "disabled" sentinel) pass through.
 * The value must be a canonical decimal integer: leading/trailing
 * whitespace, a '+' sign and trailing garbage are rejected, matching
 * parse_uint (the parser behind the CLI numbers and IWAN_SRV_THREADS). */
long long env_ms_range(const char *name, long long defval, long long min,
                       long long max, int allow_zero,
                       const char *range_desc);

/* ---------------- shared parsing / buffer-growth helpers ---------------- */

/* 0-15 for a hex digit ('0'-'9', 'a'-'f', 'A'-'F'), else -1 */
static inline int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Grow a heap buffer's capacity. `used` is the current fill, `extra` the
 * additional capacity that must become representable, `cap` the current
 * capacity, `init` the capacity of a fresh empty buffer (used when
 * cap==0), `esize` the size of one element in bytes (1 for a byte
 * buffer). Doubles from the current capacity until `used + extra` fits,
 * degrading to the exact needed size at the size_t ceiling (both the *2
 * and the byte-size multiply are guarded). Returns the new capacity
 * (stored in *newcap; == cap when nothing needed to grow), or 0 when
 * `used + extra` is not representable (callers abort: allocation failure
 * is fatal in this codebase). */
size_t grow_cap(size_t used, size_t extra, size_t cap, size_t init,
                size_t esize, size_t *newcap);

/* ---------- shared NUL-terminated growable byte buffer ---------- */

/* Growable string buffer that is always kept NUL-terminated (one byte
 * past len). `d` may be NULL while empty {0} is still NUL-terminatable;
 * callers treat d+len as the contents. Single shared definition: json.c
 * (jbuf) and https.c (sbuf) used to carry verbatim local copies. */
typedef struct sbuf {
    char  *d;
    size_t len;
    size_t cap;
} sbuf;

/* append n bytes from p to s, growing as needed; s remains NUL-terminated.
 * Allocation failure is fatal (oom_abort). */
void sbuf_app(sbuf *s, const void *p, size_t n);

/* parse_uint result codes (the function itself is declared in common.h;
 * the three-state contract below supersedes its "0/-1" doc comment):
 * 0 on success; on failure the code tells check_uint (cli.c) which clap
 * message to emit without re-scanning the string. */
enum {
    PARSE_UINT_OK = 0,     /* parsed; *out holds the value */
    PARSE_UINT_BAD = -1,   /* empty string or a non-digit character */
    PARSE_UINT_RANGE = -2, /* all digits, but the value exceeds max */
};

/* ---------------- process-wide signal state ---------------- */

/* shared stop flag: written by SIGINT/SIGTERM handlers (relaxed atomic
 * store: lock-free on every supported target), read by the event loops.
 * Defined once in util.c; socks.c/proxy.c/iwan_server.c use it instead of
 * private copies. */
extern atomic_bool g_stop;
/* set (with g_stop) by the SIGINT/SIGTERM/console-ctrl handler only;
 * lets reconnect loops distinguish "user pressed Ctrl-C" from the
 * pump's own session-loss flag (which also sets g_stop) */
extern atomic_bool g_user_stop;
/* SIG_IGN SIGPIPE once per process: pipe writes then surface EPIPE
 * instead of killing the process. Call at the top of each main(). */
void util_ignore_sigpipe(void);

/* monotonic microsecond clock (defined in util.c). The pump's fine-grained
 * batch-latency cap and the pacing bucket use it; now_ms() (common.h) is
 * the millisecond-resolution timeout clock. */
uint64_t now_us(void);

/* ---------------- aggregate send pacing (optional) ---------------- */

/* Token-bucket pacing for the aggregate UDP send rate. This is the
 * shared implementation of what used to be two verbatim copies in
 * socks.c and proxy.c.
 *
 * Enabled only when the environment variable IWAN_SEND_PACING_PPS is set
 * to a rate in 1..10000000 packets/s; unset/empty and an explicit 0 (the
 * documented "disabled" sentinel) both leave pacing off (default: 0 =
 * disabled). The pacing exists because
 * the Rust reference server's single-threaded drain (~360k pps) silently
 * drops UDP bursts past its rcvbuf, collapsing the inner TCP into an RTO
 * storm; the C server in this repo has no such ceiling, so no pacing is
 * applied unless explicitly requested (IWAN_SEND_PACING_PPS=300000).
 *
 * Not thread-safe: callers with concurrent senders (proxy.c pump threads)
 * must serialize pace_take with their send lock. */
typedef struct {
    uint32_t pps;      /* 0 = disabled */
    uint64_t budget;   /* unused send budget, in packets */
    uint64_t last;     /* last refill timestamp (us) */
} pace_bucket;

void pace_bucket_init(pace_bucket *b);   /* reads IWAN_SEND_PACING_PPS */
/* account npk packets against the bucket, sleeping when over budget */
void pace_take(pace_bucket *b, int npk);

#endif
