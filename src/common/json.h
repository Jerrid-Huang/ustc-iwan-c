#ifndef IWAN_JSON_H
#define IWAN_JSON_H

#include <stddef.h>

typedef struct Json Json;

enum { JSON_NULL, JSON_BOOL, JSON_NUM, JSON_STR, JSON_ARR, JSON_OBJ };

/* parse text; NULL on error. Returned tree freed with json_free (deep). */
Json       *json_parse(const char *text);
/* parse with serde-style error message (e.g. "expected `,` or `}` at line 1 column 8") */
Json       *json_parse_ex(const char *text, char *err, size_t errsz);
void        json_free(Json *j);
int         json_type(const Json *j);
const char *json_str(const Json *j);    /* JSON_STR -> string, else NULL */
double      json_num(const Json *j);    /* JSON_NUM -> value, else 0 */
int         json_bool(const Json *j);   /* JSON_BOOL -> 1/0 */
size_t      json_arr_len(const Json *j);
Json       *json_arr_at(Json *j, size_t i);
Json       *json_obj_get(Json *j, const char *key); /* NULL if missing */
/* deep lookup path "a.b.0.c": numeric segments index arrays */
Json       *json_get(Json *root, const char *path);
/* convenience: string at path or NULL */
const char *json_get_str(Json *root, const char *path);
/* escape a string for embedding in JSON output. Caller frees. */
char       *json_escape(const char *s);

#endif
