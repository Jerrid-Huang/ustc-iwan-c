#ifndef IWAN_CLI_H
#define IWAN_CLI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Table-driven CLI parser shared by iwan-client and iwan-client-oidc.
 * Mimics the clap-style option grammar both programs already speak:
 *   --name VALUE | --name=VALUE | --flag, plus optional single-letter aliases.
 * On -h/--help and -V/--version the callbacks take over (they may not return:
 * each program prints its own help/version and exits).
 */

typedef enum {
    CLI_OPT_BOOL,
    CLI_OPT_STR,
    CLI_OPT_U8,
    CLI_OPT_U16,
    CLI_OPT_CSV,
} cli_opt_kind;

typedef struct {
    const char *name;
    cli_opt_kind kind;
    void       *dst;
    const char *valname;   /* NULL for BOOL */
    /*
     * Optional per-value validator. Run right after the value is bound.
     * Return true on success; on failure fill err(errsz) with the reason.
     */
    bool (*validate)(const char *val, char *err, size_t errsz);
} cli_opt;

#define CLI_MAX_USAGE 16

#define CLI_INIT_CTL { 0 }

typedef struct cli_ctl {
    /* -h/--help; long_help distinguishes "--help" from "-h". Must exit. */
    void (*on_help)(bool long_help);
    /* -V/--version, used only when !version_is_unknown. Must exit. */
    void (*on_version)(void);
    /* Treat -V/--version as an unexpected argument (iwan-client subcommands). */
    bool version_is_unknown;
    /* Usage line printed under "unexpected argument" errors. */
    const char *(*usage_str)(void);
    /* Single-letter aliases, NULL-terminated {"short","--long"} pairs. */
    const char *const (*short_aliases)[2];
    /* Collect unique flags in CLI order for "smart" usage (oidc). */
    bool track_usage;
} cli_ctl;

typedef struct {
    char        usage_names[CLI_MAX_USAGE][24];
    char        usage_args[CLI_MAX_USAGE][48];
    int         nusage;
    bool        usage_dup;
    const char *dup_name;
    const char *dup_valname;
} Cli;

void cli_init(Cli *c);
/* Parse argv[start..argc). Never returns: help/version/errors exit(0)/exit(2). */
void cli_parse(Cli *c, int argc, char **argv, int start,
               const cli_opt *opts, size_t nopts, const cli_ctl *ctl);

#endif