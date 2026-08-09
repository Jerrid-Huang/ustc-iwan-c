/* Config file load/save and the /m/config remote fetch. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "json.h"
#include "oidc.h"
#include "util.h"

static long server_port(Json *s)
{
    Json *p = json_get(s, "serverPort");
    if (p && json_type(p) == JSON_NUM)
        return (long)json_num(p);
    if (p && json_type(p) == JSON_STR)
        return atol(json_str(p));
    return 0;
}

static void mkdir_p(const char *path)
{
    char tmp[4096];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof tmp)
        oidc_die("config dir path too long");
    memcpy(tmp, path, n + 1);
    if (tmp[n - 1] == '/')
        tmp[n - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
                oidc_die("cannot create dir %s: %s", tmp, strerror(errno));
            *p = '/';
        }
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
        oidc_die("cannot create dir %s: %s", tmp, strerror(errno));
}

void oidc_fetch_config(Config *cf)
{
    char *kp = NULL;
    char *username = NULL;
    oidc_login(&kp, &username);

    uint8_t rb[8];
    oidc_rand_bytes(rb, sizeof rb);
    char device_id[17];
    hex_encode(rb, sizeof rb, device_id);
    if (debug_enabled())
        oidc_eprintf("  device_id=%s\n", device_id);

    char *dev_body = oidc_build_dev_body("android", device_id, username);
    char *ka_body = oidc_build_dev_body("keepalive", device_id, username);

    oidc_eprintf("  Registering device... ");
    fflush(stderr);
    char *resp = NULL;
    int st = oidc_ctrl_post("/m/auth", dev_body, kp, &resp);
    if (st != 200) {
        const char *detail = resp ? resp : "";
        free(resp);
        oidc_die("fail HTTP %d: %s", st, detail);
    }
    free(resp);
    oidc_eprintf("OK\n");

    st = oidc_ctrl_post("/m/keepalive", ka_body, kp, &resp);
    free(resp);
    if (st != 200)
        oidc_die("keepalive failed HTTP %d", st);

    oidc_eprintf("  Fetching server config... ");
    fflush(stderr);
    st = oidc_ctrl_post("/m/config", dev_body, kp, &resp);
    free(dev_body);
    free(ka_body);
    if (st != 200)
        oidc_die("fail HTTP %d: %s", st, resp ? resp : "");
    oidc_eprintf("OK\n");

    Json *respj = json_parse(resp);
    free(resp);
    if (!respj)
        oidc_die("cannot parse /m/config response");
    Json *raw = json_get(respj, "serverlist.serverlist");
    size_t n = (raw && json_type(raw) == JSON_ARR) ? json_arr_len(raw) : 0;

    buf_t b;
    buf_init(&b);
    buf_put_str(&b, "{\n  \"domain\": \"" OIDC_DOMAIN "\",\n  \"servers\": [\n");
    for (size_t i = 0; i < n; i++) {
        Json *s = json_arr_at(raw, i);
        buf_put_str(&b, "    {\n");
        buf_put_str(&b, "      \"name\": \"");
        oidc_esc_put(&b, json_get_str(s, "name"));
        buf_put_str(&b, "\",\n      \"host\": \"");
        oidc_esc_put(&b, json_get_str(s, "serverName"));
        buf_put_str(&b, "\",\n");
        long port = server_port(s);
        if (port != 0) {
            char pbuf[64];
            snprintf(pbuf, sizeof pbuf, "      \"port\": %ld,\n", port);
            buf_put_str(&b, pbuf);
        }
        buf_put_str(&b, "      \"username\": \"");
        oidc_esc_put(&b, json_get_str(s, "userName"));
        buf_put_str(&b, "\",\n      \"passWord\": \"");
        oidc_esc_put(&b, json_get_str(s, "passWord"));
        buf_put_str(&b, "\"\n    }");
        if (i + 1 < n)
            buf_put_str(&b, ",");
        buf_put_str(&b, "\n");
    }
    buf_put_str(&b, "  ]\n}\n");
    oidc_buf_cstr(&b);
    json_free(respj);

    Json *root = json_parse((char *)b.data);
    if (!root)
        oidc_die("cannot parse generated config");
    cf->domain = xstrdup(OIDC_DOMAIN);
    cf->root = root;
    cf->servers = json_get(root, "servers");
    cf->pretty = oidc_buf_to_cstr(&b);

    free(kp);
    free(username);
}

/* --all re-execs via sudo, so the fresh file (and any dir we just
 * created) are root-owned; hand both back to the invoking user, or
 * the next non-sudo run cannot read or rewrite the config */
static void restore_owner(const char *path, const char *dir)
{
    const char *su = getenv("SUDO_UID");
    const char *sg = getenv("SUDO_GID");
    if (getuid() == 0 && su && sg) {
        uid_t uid = (uid_t)strtoul(su, NULL, 10);
        gid_t gid = (gid_t)strtoul(sg, NULL, 10);
        if (chown(path, uid, gid) != 0)
            oidc_die("cannot chown config %s: %s", path, strerror(errno));
        if (dir && chown(dir, uid, gid) != 0)
            oidc_die("cannot chown config dir %s: %s", dir,
                     strerror(errno));
    }
}

void oidc_save_config(const char *path, const Config *cf)
{
    if (!cf->servers || json_type(cf->servers) != JSON_ARR ||
        json_arr_len(cf->servers) == 0)
        oidc_die("cannot save config: server list is empty "
                 "(refusing to write an unusable config)");

    const char *slash = strrchr(path, '/');
    char *dir = NULL;
    if (slash && slash != path) {
        dir = malloc((size_t)(slash - path) + 1);
        memcpy(dir, path, (size_t)(slash - path));
        dir[slash - path] = '\0';
        mkdir_p(dir);
    }
    /* write a sibling temp file, then rename() over the target so the
     * config is replaced atomically: a concurrent reader never sees a
     * half-written file. Same directory keeps rename() on one filesystem.
     * O_NOFOLLOW: this runs as root (sudo re-exec) writing into the
     * invoking user's home; a pre-planted symlink at the temp path must
     * not become an arbitrary-root-file truncate/overwrite primitive */
    size_t tlen = strlen(path) + sizeof ".tmp";
    char *tmp = malloc(tlen);
    snprintf(tmp, tlen, "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0)
        oidc_die("cannot write config to %s", path);
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlink(tmp);
        oidc_die("cannot write config to %s", path);
    }
    /* the file holds decryptable password blobs: never world-readable */
    (void)fchmod(fileno(f), 0600);
    if (fputs(cf->pretty, f) == EOF || fflush(f) != 0 ||
        fsync(fileno(f)) != 0 || fclose(f) != 0) {
        unlink(tmp);
        oidc_die("cannot write config to %s: %s", path, strerror(errno));
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        oidc_die("cannot write config to %s: %s", path, strerror(errno));
    }
    free(tmp);

    restore_owner(path, dir);
    free(dir);
    oidc_eprintf("  Saved %zu server(s) to %s\n", json_arr_len(cf->servers),
                 path);
}

void oidc_load_config(const char *path, Config *cf)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        char msg[512];
        snprintf(msg, sizeof msg,
                 "cannot read config file %s (run iwan-client-oidc --fetch first)",
                 path);
        oidc_die_with_cause(msg, strerror(errno));
    }
    buf_t b;
    buf_init(&b);
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0)
        buf_put(&b, tmp, n);
    fclose(f);
    oidc_buf_cstr(&b);

    char jerr[160];
    Json *root = json_parse_ex((char *)b.data, jerr, sizeof jerr);
    buf_free(&b);
    if (!root)
        oidc_die_with_cause("parse config", jerr);
    Json *servers = json_get(root, "servers");
    if (!servers || json_type(servers) != JSON_ARR) {
        json_free(root);
        oidc_die("config missing servers array");
    }
    const char *dom = json_get_str(root, "domain");
    cf->domain = xstrdup(dom && *dom ? dom : OIDC_DOMAIN);
    cf->root = root;
    cf->servers = servers;
    cf->pretty = NULL;
}

void oidc_config_free(Config *cf)
{
    free(cf->domain);
    free(cf->pretty);
    json_free(cf->root);
    memset(cf, 0, sizeof *cf);
}