#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static void usage_exit(const cli_ctl *ctl)
{
    fprintf(stderr, "\n\n%s\n\nFor more information, try '--help'.\n",
            ctl->usage_str ? ctl->usage_str() : "");
    exit(2);
}

static void err_unknown(const cli_ctl *ctl, const char *arg)
{
    fprintf(stderr, "error: unexpected argument '%s' found", arg);
    usage_exit(ctl);
}

static void err_need_value(const cli_ctl *ctl, const char *name,
                           const char *valname)
{
    fprintf(stderr,
            "error: a value is required for '--%s %s' but none was supplied",
            name, valname);
    fprintf(stderr, "\n\n%s\n\nFor more information, try '--help'.\n",
            ctl->usage_str ? ctl->usage_str() : "");
    exit(2);
}

static void err_bad_value(const cli_ctl *ctl, const char *name,
                          const char *valname, const char *val,
                          const char *why)
{
    fprintf(stderr, "error: invalid value '%s' for '--%s %s': %s",
            val, name, valname, why);
    fprintf(stderr, "\n\n%s\n\nFor more information, try '--help'.\n",
            ctl->usage_str ? ctl->usage_str() : "");
    exit(2);
}

static void err_bool_value(const cli_ctl *ctl, const char *name,
                           const char *val)
{
    fprintf(stderr,
            "error: unexpected value '%s' for '--%s' found; no more were expected",
            val, name);
    usage_exit(ctl);
}

/* validate and parse an unsigned value; returns it, or exits with a
 * clap-style error. The actual parsing lives in the shared parse_uint
 * (common.h); here we only classify the failure into a message. */
static uint64_t check_uint(const cli_ctl *ctl, const char *name,
                           const char *valname, const char *val,
                           uint64_t max, const char *maxstr)
{
    uint64_t v;
    if (parse_uint(val, max, &v) != 0) {
        if (*val == '\0')
            err_bad_value(ctl, name, valname, val,
                          "cannot parse integer from empty string");
        for (const char *p = val; *p; p++)
            if (*p < '0' || *p > '9')
                err_bad_value(ctl, name, valname, val,
                              "invalid digit found in string");
        char msg[96];
        snprintf(msg, sizeof msg, "%s is not in 0..=%s", val, maxstr);
        err_bad_value(ctl, name, valname, val, msg);
    }
    return v;
}

static const cli_opt *find_opt(const cli_opt *opts, size_t nopts,
                               const char *name, size_t nlen)
{
    for (size_t j = 0; j < nopts; j++) {
        if (strlen(opts[j].name) == nlen &&
            strncmp(name, opts[j].name, nlen) == 0)
            return &opts[j];
    }
    return NULL;
}

static const char *map_short(const cli_ctl *ctl, const char *a)
{
    char ch;

    /* single-dash single-char form only ("-c"): clap-style parsers do not
     * accept "--c", and accepting it would mask typos */
    if (!ctl->short_aliases || a[0] != '-' || a[1] == '-')
        return NULL;
    if (a[2] != '\0')
        return NULL;
    ch = a[1];
    for (const char *const(*p)[2] = ctl->short_aliases; (*p)[0]; p++)
        if (ch == (*p)[0][0])
            return (*p)[1];
    return NULL;
}

/* Every short alias must target an option that exists in the table: a
 * stale alias would otherwise surface as a confusing internal long name
 * in errors (this bit the codebase once with a dead -c alias). */
static void validate_aliases(const cli_opt *opts, size_t nopts,
                             const cli_ctl *ctl)
{
    if (!ctl->short_aliases)
        return;
    for (const char *const(*p)[2] = ctl->short_aliases; (*p)[0]; p++) {
        if (find_opt(opts, nopts, (*p)[1] + 2, strlen((*p)[1] + 2)) == NULL) {
            fprintf(stderr,
                    "error: internal: short alias '%s' targets unknown "
                    "option '%s'\n", (*p)[0], (*p)[1]);
            exit(2);
        }
    }
}

/* Record the option's canonical name and detect duplicates. Duplicate
 * detection is unconditional (clap semantics for every binary); the
 * usage_names list is only consumed by oidc's "smart usage" renderer,
 * so recording it unconditionally is harmless. */
static void track_flag(Cli *c, const cli_opt *o, const cli_ctl *ctl)
{
    (void)ctl;
    for (int j = 0; j < c->nusage; j++)
        if (strcmp(c->usage_names[j], o->name) == 0) {
            if (o->kind == CLI_OPT_BOOL) {
                /* clap: bool dups error at the second occurrence */
                c->usage_dup = true;
                fprintf(stderr,
                        "error: the argument '--%s' cannot be used multiple times",
                        o->name);
                usage_exit(ctl);
            }
            if (o->kind != CLI_OPT_CSV) {
                /* value dups error after full parse; keep the first one */
                c->usage_dup = true;
                if (!c->dup_name) {
                    c->dup_name = o->name;
                    c->dup_valname = o->valname;
                }
            }
            return;   /* CSV: repeated freely; usage renders the flag once */
        }
    if (c->nusage < CLI_MAX_USAGE) {
        snprintf(c->usage_names[c->nusage],
                 sizeof c->usage_names[c->nusage], "%s", o->name);
        if (o->valname)
            snprintf(c->usage_args[c->nusage],
                     sizeof c->usage_args[c->nusage], "--%s %s",
                     o->name, o->valname);
        else
            snprintf(c->usage_args[c->nusage],
                     sizeof c->usage_args[c->nusage], "--%s", o->name);
        c->nusage++;
    }
}

static void store_value(const cli_opt *o, const char *val, uint64_t parsed)
{
    switch (o->kind) {
    case CLI_OPT_STR:
        *(const char **)o->dst = val;
        break;
    case CLI_OPT_U8:
        *(uint8_t *)o->dst = (uint8_t)parsed;
        break;
    case CLI_OPT_U16:
        *(uint16_t *)o->dst = (uint16_t)parsed;
        break;
    case CLI_OPT_CSV:
        slist_push_csv((slist_t *)o->dst, val);
        break;
    case CLI_OPT_BOOL:
        break;
    }
}

void cli_init(Cli *c)
{
    memset(c, 0, sizeof *c);
}

void cli_parse(Cli *c, int argc, char **argv, int start,
               const cli_opt *opts, size_t nopts, const cli_ctl *ctl)
{
    validate_aliases(opts, nopts, ctl);
    for (int i = start; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0) {
            ctl->on_help(false);
            exit(0);
        }
        if (strcmp(a, "--help") == 0) {
            ctl->on_help(true);
            exit(0);
        }
        if (strcmp(a, "-V") == 0 || strcmp(a, "--version") == 0) {
            if (ctl->version_is_unknown)
                err_unknown(ctl, a);
            ctl->on_version();
            exit(0);
        }
        const char *long_form = map_short(ctl, a);
        if (long_form)
            a = long_form;
        if (a[0] != '-' || a[1] != '-')
            err_unknown(ctl, a);
        const char *name = a + 2;
        const char *eq = strchr(name, '=');
        size_t nlen = eq ? (size_t)(eq - name) : strlen(name);
        const char *val = eq ? eq + 1 : NULL;

        const cli_opt *o = find_opt(opts, nopts, name, nlen);
        if (!o)
            err_unknown(ctl, a);

        /* duplicate detection is unconditional (clap semantics) */
        track_flag(c, o, ctl);

        if (o->kind == CLI_OPT_BOOL) {
            *(bool *)o->dst = true;
            if (val)
                err_bool_value(ctl, o->name, val);
            continue;
        }
        if (!val) {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
                err_need_value(ctl, o->name, o->valname);
            val = argv[++i];
        }
        uint64_t parsed = 0;
        switch (o->kind) {
        case CLI_OPT_U8:
            parsed = check_uint(ctl, o->name, o->valname, val, UINT8_MAX,
                                "255");
            break;
        case CLI_OPT_U16:
            parsed = check_uint(ctl, o->name, o->valname, val, UINT16_MAX,
                                "65535");
            break;
        default:
            break;
        }
        if (o->validate) {
            char err[160];
            if (!o->validate(val, err, sizeof err))
                err_bad_value(ctl, o->name, o->valname, val, err);
        }
        store_value(o, val, parsed);
    }

    /* clap validates value-arg duplicates after the full parse */
    if (c->dup_name) {
        fprintf(stderr,
                "error: the argument '--%s %s' cannot be used multiple times",
                c->dup_name, c->dup_valname);
        usage_exit(ctl);
    }
}