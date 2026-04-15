#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "php_blake3.h"
#include "c/blake3.h"

#define PHP_BLAKE3_MAX_OUTPUT (64 * 1024 * 1024)

static zend_class_entry *php_blake3_context_ce;
static zend_object_handlers php_blake3_context_handlers;

typedef struct _php_blake3_context_obj {
  zend_object   std;
  blake3_hasher hasher;
  zend_bool     b_finalised;
} php_blake3_context_obj;

static inline php_blake3_context_obj *php_blake3_obj(zend_object *p_obj)
{
  return (php_blake3_context_obj *)((char *)p_obj - XtOffsetOf(php_blake3_context_obj, std));
}

#define PHP_BLAKE3_OBJ_P(zv) php_blake3_obj(Z_OBJ_P(zv))

static inline void php_blake3_secure_zero(void *pv, size_t ul_len)
{
#if defined(HAVE_EXPLICIT_BZERO)
  explicit_bzero(pv, ul_len);
#elif defined(HAVE_MEMSET_S)
  memset_s(pv, ul_len, 0, ul_len);
#elif defined(_WIN32)
  SecureZeroMemory(pv, ul_len);
#else
  volatile unsigned char *p_uc = (volatile unsigned char *)pv;
  while (ul_len--) *p_uc++ = 0;
#endif
}

static void php_blake3_free_obj(zend_object *p_obj)
{
  php_blake3_context_obj *p_ctx = php_blake3_obj(p_obj);
  php_blake3_secure_zero(&p_ctx->hasher, sizeof(blake3_hasher));
  zend_object_std_dtor(p_obj);
}

static HashTable *php_blake3_get_gc(zend_object *p_obj, zval **pp_table, int *n)
{
  *pp_table = NULL;
  *n = 0;
  return NULL;
}

static HashTable *php_blake3_get_properties(zend_object *p_obj)
{
  (void)p_obj;
  return NULL;
}

static zend_object *php_blake3_create_obj(zend_class_entry *p_ce)
{
  php_blake3_context_obj *p_ctx = zend_object_alloc(
    sizeof(php_blake3_context_obj), p_ce);
  zend_object_std_init(&p_ctx->std, p_ce);
  p_ctx->std.handlers = &php_blake3_context_handlers;
  p_ctx->b_finalised = 0;
  return &p_ctx->std;
}

static zend_object *php_blake3_create_forbidden(zend_class_entry *p_ce)
{
  zend_object *p_obj = php_blake3_create_obj(p_ce);
  zend_throw_exception_ex(zend_ce_error, 0,
    "Blake3Context cannot be instantiated directly, use blake3_init() instead");
  return p_obj;
}

static zend_object *php_blake3_clone_obj(zend_object *p_old)
{
  php_blake3_context_obj *p_old_ctx = php_blake3_obj(p_old);
  zend_object            *p_new     = php_blake3_create_obj(p_old->ce);
  php_blake3_context_obj *p_new_ctx = php_blake3_obj(p_new);
  memcpy(&p_new_ctx->hasher, &p_old_ctx->hasher, sizeof(blake3_hasher));
  p_new_ctx->b_finalised = p_old_ctx->b_finalised;
  zend_objects_clone_members(p_new, p_old);
  return p_new;
}

static php_blake3_context_obj *php_blake3_fetch_obj(zval *p_zv, const char *pc_fn)
{
  php_blake3_context_obj *p_ctx = PHP_BLAKE3_OBJ_P(p_zv);
  if (UNEXPECTED(p_ctx->b_finalised)) {
    zend_throw_exception_ex(zend_ce_error, 0,
      "%s(): context has already been finalised", pc_fn);
    return NULL;
  }
  return p_ctx;
}

static zend_string *php_blake3_bytes_to_hex(const unsigned char *p_uc, size_t ul_len)
{
  if (UNEXPECTED(ul_len == 0)) {
    return ZSTR_EMPTY_ALLOC();
  }
  zend_string *s_hex = zend_string_alloc(ul_len * 2, 0);
  if (UNEXPECTED(s_hex == NULL)) return NULL;
  static const char c_hx[] = "0123456789abcdef";
  for (size_t ul_i = 0; ul_i < ul_len; ul_i++) {
    ZSTR_VAL(s_hex)[ul_i * 2]     = c_hx[(p_uc[ul_i] >> 4) & 0x0F];
    ZSTR_VAL(s_hex)[ul_i * 2 + 1] = c_hx[p_uc[ul_i] & 0x0F];
  }
  ZSTR_VAL(s_hex)[ul_len * 2] = '\0';
  return s_hex;
}

static inline zend_result php_blake3_check_key(zend_string *s_key, int i_pos)
{
  if (UNEXPECTED(ZSTR_LEN(s_key) != BLAKE3_KEY_LEN)) {
    zend_argument_value_error(i_pos,
      "must be exactly %d bytes, %zd given",
      BLAKE3_KEY_LEN, ZSTR_LEN(s_key));
    return FAILURE;
  }
  return SUCCESS;
}

typedef enum _php_blake3_hash_mode {
  PHP_BLAKE3_MODE_DEFAULT,
  PHP_BLAKE3_MODE_KEYED,
  PHP_BLAKE3_MODE_DERIVE_KEY,
} php_blake3_hash_mode;

typedef struct _php_blake3_hash_opts {
  php_blake3_hash_mode  e_mode;
  const char           *pc_key;       /* only if e_mode == KEYED */
  const char           *pc_context;   /* only if e_mode == DERIVE_KEY */
  zend_long             ul_olen;
  zend_bool             b_raw;
} php_blake3_hash_opts;

static inline zend_result php_blake3_hasher_init_ex(blake3_hasher *p_h, const php_blake3_hash_opts *p_opts)
{
  switch (p_opts->e_mode) {
    case PHP_BLAKE3_MODE_KEYED:
      blake3_hasher_init_keyed(p_h, (const uint8_t *)p_opts->pc_key);
      break;
    case PHP_BLAKE3_MODE_DERIVE_KEY:
      blake3_hasher_init_derive_key(p_h, p_opts->pc_context);
      break;
    case PHP_BLAKE3_MODE_DEFAULT:
    default:
      blake3_hasher_init(p_h);
      break;
  }
  return SUCCESS;
}

static inline zend_string *php_blake3_do_hash_ex(const unsigned char *p_in, size_t ul_in_len,
                                                  const php_blake3_hash_opts *p_opts)
{
  unsigned char *p_out = NULL;
  zend_string   *s_ret  = NULL;

  p_out = (unsigned char *)safe_emalloc((size_t)p_opts->ul_olen, 1, 0);
  if (UNEXPECTED(p_out == NULL)) {
    return NULL;
  }

  blake3_hasher h;
  php_blake3_hasher_init_ex(&h, p_opts);
  blake3_hasher_update(&h, p_in, ul_in_len);
  blake3_hasher_finalize(&h, p_out, (size_t)p_opts->ul_olen);
  php_blake3_secure_zero(&h, sizeof(h));

  if (p_opts->b_raw) {
    s_ret = zend_string_init((const char *)p_out, (size_t)p_opts->ul_olen, 0);
  } else {
    s_ret = php_blake3_bytes_to_hex(p_out, (size_t)p_opts->ul_olen);
  }
  php_blake3_secure_zero(p_out, (size_t)p_opts->ul_olen);
  efree(p_out);
  return s_ret;
}

PHP_METHOD(Blake3Context, update)
{
  zend_string *s_input;
  ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STR(s_input)
  ZEND_PARSE_PARAMETERS_END();

  php_blake3_context_obj *p_ctx =
    php_blake3_fetch_obj(ZEND_THIS, "Blake3Context::update");
  if (!p_ctx) RETURN_THROWS();
  blake3_hasher_update(&p_ctx->hasher,
            ZSTR_VAL(s_input), ZSTR_LEN(s_input));
}

PHP_METHOD(Blake3Context, final)
{
  zend_bool b_raw = 0;
  ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(b_raw)
  ZEND_PARSE_PARAMETERS_END();

  php_blake3_context_obj *p_ctx =
    php_blake3_fetch_obj(ZEND_THIS, "Blake3Context::final");
  if (!p_ctx) RETURN_THROWS();

  unsigned char uc_hash[BLAKE3_OUT_LEN];
  blake3_hasher_finalize(&p_ctx->hasher, uc_hash, BLAKE3_OUT_LEN);
  p_ctx->b_finalised = 1;

  if (b_raw) {
    RETURN_STRINGL((char *)uc_hash, BLAKE3_OUT_LEN);
  }
  zend_string *s_hex = php_blake3_bytes_to_hex(uc_hash, BLAKE3_OUT_LEN);
  if (!s_hex) RETURN_FALSE;
  RETURN_STR(s_hex);
}

static const zend_function_entry php_blake3_ctx_methods[] = {
  PHP_ME(Blake3Context, update, arginfo_blake3_update,  ZEND_ACC_PUBLIC)
  PHP_ME(Blake3Context, final,  arginfo_blake3_final,   ZEND_ACC_PUBLIC)
  PHP_FE_END
};

static const zend_function_entry php_blake3_functions[] = {
  PHP_FE(blake3,            arginfo_blake3)
  PHP_FE(blake3_file,       arginfo_blake3_file)
  PHP_FE(blake3_init,       arginfo_blake3_init)
  PHP_FE(blake3_update,     arginfo_blake3_update_fn)
  PHP_FE(blake3_final,      arginfo_blake3_final_fn)
  PHP_FE(blake3_reset,      arginfo_blake3_reset_fn)
  PHP_FE(blake3_derive_key, arginfo_blake3_derive_key)
  PHP_FE(blake3_xof,        arginfo_blake3_xof)
  PHP_FE(blake3_version,    arginfo_blake3_version)
  PHP_FE(blake3_hash,       arginfo_blake3_hash)
  PHP_FE(blake3_hash_raw,   arginfo_blake3_hash_raw)
  PHP_FE(blake3_keyed_hash, arginfo_blake3_keyed_hash)
  PHP_FE_END
};

static PHP_MINFO_FUNCTION(blake3)
{
  php_info_print_table_start();
  php_info_print_table_header(2, "blake3 support", "enabled");
  php_info_print_table_row(2, "BLAKE3 library version", BLAKE3_VERSION_STRING);
  php_info_print_table_row(2, "Extension version", PHP_BLAKE3_VERSION);
  php_info_print_table_row(2, "Max output length", "64 MB");
  php_info_print_table_row(2, "SIMD support",
#if defined(IS_X86)
    "AVX-512, AVX2, SSE4.1, SSE2"
#elif BLAKE3_USE_NEON == 1
    "NEON (ARM)"
#else
    "Portable C only"
#endif
  );
  php_info_print_table_row(2, "Secure zero",
#if defined(HAVE_EXPLICIT_BZERO)
    "explicit_bzero"
#elif defined(HAVE_MEMSET_S)
    "memset_s"
#elif defined(_WIN32)
    "SecureZeroMemory"
#else
    "volatile fallback"
#endif
  );
  php_info_print_table_end();
}

static PHP_MINIT_FUNCTION(blake3)
{
  zend_class_entry ce;
  INIT_CLASS_ENTRY(ce, "Blake3Context", php_blake3_ctx_methods);
  php_blake3_context_ce = zend_register_internal_class(&ce);
  php_blake3_context_ce->create_object  = php_blake3_create_forbidden;
  php_blake3_context_ce->ce_flags |=
    ZEND_ACC_FINAL |
    ZEND_ACC_NO_DYNAMIC_PROPERTIES |
    ZEND_ACC_NOT_SERIALIZABLE;

  /*
   * Start from std_object_handlers so all required slots (dtor_obj,
   * read_property, get_method, cast_object, compare …) are valid.
   * Then override only the handlers that must behave differently:
   *  - clone_obj: custom deep-copy of the 1.9 KB hasher struct
   *  - free_obj:  secure-zero before release
   *  - get_properties / get_gc: no user-visible properties
   */
  memcpy(&php_blake3_context_handlers,
         zend_get_std_object_handlers(),
         sizeof(zend_object_handlers));
  php_blake3_context_handlers.offset        =
    XtOffsetOf(php_blake3_context_obj, std);
  php_blake3_context_handlers.clone_obj     = php_blake3_clone_obj;
  php_blake3_context_handlers.free_obj      = php_blake3_free_obj;
  php_blake3_context_handlers.get_properties = php_blake3_get_properties;
  php_blake3_context_handlers.get_gc        = php_blake3_get_gc;

  REGISTER_LONG_CONSTANT("BLAKE3_OUT_LEN",    BLAKE3_OUT_LEN,
              CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("BLAKE3_KEY_LEN",     BLAKE3_KEY_LEN,
              CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("BLAKE3_BLOCK_LEN",   BLAKE3_BLOCK_LEN,
              CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("BLAKE3_MAX_DEPTH",   BLAKE3_MAX_DEPTH,
              CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("BLAKE3_MAX_OUTPUT",  PHP_BLAKE3_MAX_OUTPUT,
              CONST_CS | CONST_PERSISTENT);

  return SUCCESS;
}

zend_module_entry blake3_module_entry = {
  STANDARD_MODULE_HEADER,
  "blake3",
  php_blake3_functions,
  PHP_MINIT(blake3), NULL, NULL, NULL,
  PHP_MINFO(blake3),
  PHP_BLAKE3_VERSION,
  STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_BLAKE3
ZEND_GET_MODULE(blake3)
#endif

PHP_FUNCTION(blake3)
{
  zend_string *s_input;
  zend_long ul_olen = BLAKE3_OUT_LEN;
  zend_string *s_key = NULL;
  zend_bool b_raw = 0;

  ZEND_PARSE_PARAMETERS_START(1, 4)
    Z_PARAM_STR(s_input)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(ul_olen)
    Z_PARAM_STR_EX(s_key, 1, 0)
    Z_PARAM_BOOL(b_raw)
  ZEND_PARSE_PARAMETERS_END();

  if (UNEXPECTED(ul_olen < 1)) {
    zend_argument_value_error(2, "must be greater than 0");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ul_olen > PHP_BLAKE3_MAX_OUTPUT)) {
    zend_argument_value_error(2,
      "must not exceed %d bytes (64 MB)", PHP_BLAKE3_MAX_OUTPUT);
    RETURN_THROWS();
  }
  if (s_key && php_blake3_check_key(s_key, 3) == FAILURE) RETURN_THROWS();

  php_blake3_hash_opts opts = {
    .e_mode  = s_key ? PHP_BLAKE3_MODE_KEYED : PHP_BLAKE3_MODE_DEFAULT,
    .pc_key  = s_key ? ZSTR_VAL(s_key) : NULL,
    .ul_olen = ul_olen,
    .b_raw   = b_raw,
  };
  zend_string *s_ret = php_blake3_do_hash_ex(
    (const unsigned char *)ZSTR_VAL(s_input), ZSTR_LEN(s_input), &opts);
  if (UNEXPECTED(s_ret == NULL)) RETURN_FALSE;
  RETURN_STR(s_ret);
}

PHP_FUNCTION(blake3_file)
{
  zend_string *s_fname;
  zend_long ul_olen = BLAKE3_OUT_LEN;
  zend_string *s_key = NULL;
  zend_bool b_raw = 0;

  ZEND_PARSE_PARAMETERS_START(1, 4)
    Z_PARAM_STR(s_fname)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(ul_olen)
    Z_PARAM_STR_EX(s_key, 1, 0)
    Z_PARAM_BOOL(b_raw)
  ZEND_PARSE_PARAMETERS_END();

  if (UNEXPECTED(ul_olen < 1)) {
    zend_argument_value_error(2, "must be greater than 0");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ul_olen > PHP_BLAKE3_MAX_OUTPUT)) {
    zend_argument_value_error(2,
      "must not exceed %d bytes (64 MB)", PHP_BLAKE3_MAX_OUTPUT);
    RETURN_THROWS();
  }
  if (UNEXPECTED(ZSTR_LEN(s_fname) == 0)) {
    zend_argument_value_error(1, "must not be empty");
    RETURN_THROWS();
  }
  if (s_key && php_blake3_check_key(s_key, 3) == FAILURE) RETURN_THROWS();

  php_stream *p_stream = php_stream_open_wrapper(
    ZSTR_VAL(s_fname), "rb", REPORT_ERRORS, NULL);
  if (!p_stream) RETURN_FALSE;

  blake3_hasher h;
  if (s_key) blake3_hasher_init_keyed(
    &h, (const uint8_t *)ZSTR_VAL(s_key));
  else       blake3_hasher_init(&h);

  char uc_buf[8192];
  size_t ul_n;
  zend_bool b_err = 0;
  while ((ul_n = php_stream_read(p_stream, uc_buf, sizeof(uc_buf))) > 0) {
    blake3_hasher_update(&h, uc_buf, ul_n);
  }
  if (!php_stream_eof(p_stream)) b_err = 1;
  php_stream_close(p_stream);
  p_stream = NULL;

  if (UNEXPECTED(b_err)) {
    php_blake3_secure_zero(&h, sizeof(h));
    php_error_docref(NULL, E_WARNING,
      "read error on '%s'", ZSTR_VAL(s_fname));
    RETURN_FALSE;
  }

  php_blake3_hash_opts opts = {
    .e_mode  = s_key ? PHP_BLAKE3_MODE_KEYED : PHP_BLAKE3_MODE_DEFAULT,
    .pc_key  = s_key ? ZSTR_VAL(s_key) : NULL,
    .ul_olen = ul_olen,
    .b_raw   = b_raw,
  };

  unsigned char *p_out = (unsigned char *)safe_emalloc(
    (size_t)ul_olen, 1, 0);
  if (UNEXPECTED(p_out == NULL)) {
    php_blake3_secure_zero(&h, sizeof(h));
    RETURN_FALSE;
  }
  blake3_hasher_finalize(&h, p_out, (size_t)ul_olen);
  php_blake3_secure_zero(&h, sizeof(h));

  zend_string *s_ret;
  if (b_raw) {
    s_ret = zend_string_init((const char *)p_out, (size_t)ul_olen, 0);
  } else {
    s_ret = php_blake3_bytes_to_hex(p_out, (size_t)ul_olen);
  }
  php_blake3_secure_zero(p_out, (size_t)ul_olen);
  efree(p_out);

  if (UNEXPECTED(s_ret == NULL)) RETURN_FALSE;
  RETURN_STR(s_ret);
}

PHP_FUNCTION(blake3_init)
{
  zend_string *s_key = NULL;
  ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_STR_EX(s_key, 1, 0)
  ZEND_PARSE_PARAMETERS_END();

  if (s_key && php_blake3_check_key(s_key, 1) == FAILURE) RETURN_THROWS();

  zend_object *p_zobj = php_blake3_create_obj(php_blake3_context_ce);
  php_blake3_context_obj *p_ctx = php_blake3_obj(p_zobj);
  if (s_key) blake3_hasher_init_keyed(
    &p_ctx->hasher, (const uint8_t *)ZSTR_VAL(s_key));
  else       blake3_hasher_init(&p_ctx->hasher);
  p_ctx->b_finalised = 0;

  RETURN_OBJ(p_zobj);
}

PHP_FUNCTION(blake3_update)
{
  zval *p_obj;
  zend_string *s_input;
  ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_OBJECT_OF_CLASS(p_obj, php_blake3_context_ce)
    Z_PARAM_STR(s_input)
  ZEND_PARSE_PARAMETERS_END();

  php_blake3_context_obj *p_ctx =
    php_blake3_fetch_obj(p_obj, "blake3_update");
  if (!p_ctx) RETURN_THROWS();
  blake3_hasher_update(&p_ctx->hasher,
            ZSTR_VAL(s_input), ZSTR_LEN(s_input));
}

PHP_FUNCTION(blake3_final)
{
  zval *p_obj;
  zend_bool b_raw = 0;
  ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_OBJECT_OF_CLASS(p_obj, php_blake3_context_ce)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(b_raw)
  ZEND_PARSE_PARAMETERS_END();

  php_blake3_context_obj *p_ctx =
    php_blake3_fetch_obj(p_obj, "blake3_final");
  if (!p_ctx) RETURN_THROWS();

  unsigned char uc_hash[BLAKE3_OUT_LEN];
  blake3_hasher_finalize(&p_ctx->hasher, uc_hash, BLAKE3_OUT_LEN);
  p_ctx->b_finalised = 1;

  if (b_raw) {
    RETURN_STRINGL((char *)uc_hash, BLAKE3_OUT_LEN);
  }
  zend_string *s_hex = php_blake3_bytes_to_hex(uc_hash, BLAKE3_OUT_LEN);
  if (!s_hex) RETURN_FALSE;
  RETURN_STR(s_hex);
}

PHP_FUNCTION(blake3_reset)
{
  zval *p_obj;
  zend_string *s_key = NULL;
  ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_OBJECT_OF_CLASS(p_obj, php_blake3_context_ce)
    Z_PARAM_OPTIONAL
    Z_PARAM_STR_EX(s_key, 1, 0)
  ZEND_PARSE_PARAMETERS_END();

  if (s_key && php_blake3_check_key(s_key, 2) == FAILURE) RETURN_THROWS();

  php_blake3_context_obj *p_ctx = PHP_BLAKE3_OBJ_P(p_obj);
  php_blake3_secure_zero(&p_ctx->hasher, sizeof(blake3_hasher));
  if (s_key) blake3_hasher_init_keyed(
    &p_ctx->hasher, (const uint8_t *)ZSTR_VAL(s_key));
  else       blake3_hasher_init(&p_ctx->hasher);
  p_ctx->b_finalised = 0;
  RETURN_TRUE;
}

PHP_FUNCTION(blake3_derive_key)
{
  zend_string *s_context;
  zend_string *s_material;
  zend_long ul_olen = BLAKE3_OUT_LEN;
  zend_bool b_raw = 0;

  ZEND_PARSE_PARAMETERS_START(2, 4)
    Z_PARAM_STR(s_context)
    Z_PARAM_STR(s_material)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(ul_olen)
    Z_PARAM_BOOL(b_raw)
  ZEND_PARSE_PARAMETERS_END();

  if (UNEXPECTED(ZSTR_LEN(s_context) == 0)) {
    zend_argument_value_error(1, "must not be empty");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ZSTR_LEN(s_material) == 0)) {
    zend_argument_value_error(2, "must not be empty");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ul_olen < 1)) {
    zend_argument_value_error(3, "must be greater than 0");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ul_olen > PHP_BLAKE3_MAX_OUTPUT)) {
    zend_argument_value_error(3,
      "must not exceed %d bytes (64 MB)", PHP_BLAKE3_MAX_OUTPUT);
    RETURN_THROWS();
  }

  php_blake3_hash_opts opts = {
    .e_mode     = PHP_BLAKE3_MODE_DERIVE_KEY,
    .pc_context = ZSTR_VAL(s_context),
    .ul_olen    = ul_olen,
    .b_raw      = b_raw,
  };
  zend_string *s_ret = php_blake3_do_hash_ex(
    (const unsigned char *)ZSTR_VAL(s_material), ZSTR_LEN(s_material), &opts);
  if (UNEXPECTED(s_ret == NULL)) RETURN_FALSE;
  RETURN_STR(s_ret);
}

PHP_FUNCTION(blake3_xof)
{
  zend_string *s_input;
  zend_long ul_olen;
  zend_string *s_key = NULL;
  zend_bool b_raw = 0;

  ZEND_PARSE_PARAMETERS_START(2, 4)
    Z_PARAM_STR(s_input)
    Z_PARAM_LONG(ul_olen)
    Z_PARAM_OPTIONAL
    Z_PARAM_STR_EX(s_key, 1, 0)
    Z_PARAM_BOOL(b_raw)
  ZEND_PARSE_PARAMETERS_END();

  if (UNEXPECTED(ul_olen < 1)) {
    zend_argument_value_error(2, "must be greater than 0");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ul_olen > PHP_BLAKE3_MAX_OUTPUT)) {
    zend_argument_value_error(2,
      "must not exceed %d bytes (64 MB)", PHP_BLAKE3_MAX_OUTPUT);
    RETURN_THROWS();
  }
  if (s_key && php_blake3_check_key(s_key, 3) == FAILURE) RETURN_THROWS();

  php_blake3_hash_opts opts = {
    .e_mode  = s_key ? PHP_BLAKE3_MODE_KEYED : PHP_BLAKE3_MODE_DEFAULT,
    .pc_key  = s_key ? ZSTR_VAL(s_key) : NULL,
    .ul_olen = ul_olen,
    .b_raw   = b_raw,
  };
  zend_string *s_ret = php_blake3_do_hash_ex(
    (const unsigned char *)ZSTR_VAL(s_input), ZSTR_LEN(s_input), &opts);
  if (UNEXPECTED(s_ret == NULL)) RETURN_FALSE;
  RETURN_STR(s_ret);
}

PHP_FUNCTION(blake3_version)
{
  ZEND_PARSE_PARAMETERS_NONE();
  RETURN_STRING(BLAKE3_VERSION_STRING);
}

PHP_FUNCTION(blake3_hash)
{
  zend_string *s_input;
  zend_long ul_olen = BLAKE3_OUT_LEN;
  ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STR(s_input)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(ul_olen)
  ZEND_PARSE_PARAMETERS_END();

  if (UNEXPECTED(ul_olen < 1)) {
    zend_argument_value_error(2, "must be greater than 0");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ul_olen > PHP_BLAKE3_MAX_OUTPUT)) {
    zend_argument_value_error(2,
      "must not exceed %d bytes (64 MB)", PHP_BLAKE3_MAX_OUTPUT);
    RETURN_THROWS();
  }

  php_blake3_hash_opts opts = {
    .e_mode  = PHP_BLAKE3_MODE_DEFAULT,
    .ul_olen = ul_olen,
    .b_raw   = 0,
  };
  zend_string *s_ret = php_blake3_do_hash_ex(
    (const unsigned char *)ZSTR_VAL(s_input), ZSTR_LEN(s_input), &opts);
  if (UNEXPECTED(s_ret == NULL)) RETURN_FALSE;
  RETURN_STR(s_ret);
}

PHP_FUNCTION(blake3_hash_raw)
{
  zend_string *s_input;
  zend_long ul_olen = BLAKE3_OUT_LEN;
  ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STR(s_input)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(ul_olen)
  ZEND_PARSE_PARAMETERS_END();

  if (UNEXPECTED(ul_olen < 1)) {
    zend_argument_value_error(2, "must be greater than 0");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ul_olen > PHP_BLAKE3_MAX_OUTPUT)) {
    zend_argument_value_error(2,
      "must not exceed %d bytes (64 MB)", PHP_BLAKE3_MAX_OUTPUT);
    RETURN_THROWS();
  }

  php_blake3_hash_opts opts = {
    .e_mode  = PHP_BLAKE3_MODE_DEFAULT,
    .ul_olen = ul_olen,
    .b_raw   = 1,
  };
  zend_string *s_ret = php_blake3_do_hash_ex(
    (const unsigned char *)ZSTR_VAL(s_input), ZSTR_LEN(s_input), &opts);
  if (UNEXPECTED(s_ret == NULL)) RETURN_FALSE;
  RETURN_STR(s_ret);
}

PHP_FUNCTION(blake3_keyed_hash)
{
  zend_string *s_input, *s_key;
  zend_long ul_olen = BLAKE3_OUT_LEN;

  ZEND_PARSE_PARAMETERS_START(2, 3)
    Z_PARAM_STR(s_input)
    Z_PARAM_STR(s_key)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(ul_olen)
  ZEND_PARSE_PARAMETERS_END();

  if (php_blake3_check_key(s_key, 2) == FAILURE) RETURN_THROWS();
  if (UNEXPECTED(ul_olen < 1)) {
    zend_argument_value_error(3, "must be greater than 0");
    RETURN_THROWS();
  }
  if (UNEXPECTED(ul_olen > PHP_BLAKE3_MAX_OUTPUT)) {
    zend_argument_value_error(3,
      "must not exceed %d bytes (64 MB)", PHP_BLAKE3_MAX_OUTPUT);
    RETURN_THROWS();
  }

  php_blake3_hash_opts opts = {
    .e_mode  = PHP_BLAKE3_MODE_KEYED,
    .pc_key  = ZSTR_VAL(s_key),
    .ul_olen = ul_olen,
    .b_raw   = 0,
  };
  zend_string *s_ret = php_blake3_do_hash_ex(
    (const unsigned char *)ZSTR_VAL(s_input), ZSTR_LEN(s_input), &opts);
  if (UNEXPECTED(s_ret == NULL)) RETURN_FALSE;
  RETURN_STR(s_ret);
}
