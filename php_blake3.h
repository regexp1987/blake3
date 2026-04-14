#ifndef PHP_BLAKE3_H
#define PHP_BLAKE3_H

#define PHP_BLAKE3_VERSION "1.0.0"
#define PHP_BLAKE3_EXTNAME "blake3"

ZEND_BEGIN_ARG_INFO(arginfo_blake3, 0)
  ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, output_length, IS_LONG, 0, "32")
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, key, IS_STRING, 1, "null")
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, raw_output, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_blake3_file, 0)
  ZEND_ARG_TYPE_INFO(0, filename, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, output_length, IS_LONG, 0, "32")
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, key, IS_STRING, 1, "null")
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, raw_output, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_blake3_init, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, key, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_blake3_update, 0)
  ZEND_ARG_OBJ_INFO(0, ctx, Blake3Context, 0)
  ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()
#define arginfo_blake3_update_fn arginfo_blake3_update

ZEND_BEGIN_ARG_INFO(arginfo_blake3_final, 0)
  ZEND_ARG_OBJ_INFO(0, ctx, Blake3Context, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, raw_output, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()
#define arginfo_blake3_final_fn arginfo_blake3_final

ZEND_BEGIN_ARG_INFO(arginfo_blake3_reset, 0)
  ZEND_ARG_OBJ_INFO(0, ctx, Blake3Context, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, key, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()
#define arginfo_blake3_reset_fn arginfo_blake3_reset

ZEND_BEGIN_ARG_INFO(arginfo_blake3_derive_key, 0)
  ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO(0, key_material, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, output_length, IS_LONG, 0, "32")
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, raw_output, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_blake3_xof, 0)
  ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO(0, output_length, IS_LONG, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, key, IS_STRING, 1, "null")
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, raw_output, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_blake3_version, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_blake3_hash, 0)
  ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, output_length, IS_LONG, 0, "32")
ZEND_END_ARG_INFO()
#define arginfo_blake3_hash_raw arginfo_blake3_hash

ZEND_BEGIN_ARG_INFO(arginfo_blake3_keyed_hash, 0)
  ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, output_length, IS_LONG, 0, "32")
ZEND_END_ARG_INFO()

PHP_FUNCTION(blake3);
PHP_FUNCTION(blake3_file);
PHP_FUNCTION(blake3_init);
PHP_FUNCTION(blake3_update);
PHP_FUNCTION(blake3_final);
PHP_FUNCTION(blake3_reset);
PHP_FUNCTION(blake3_derive_key);
PHP_FUNCTION(blake3_xof);
PHP_FUNCTION(blake3_version);
PHP_FUNCTION(blake3_hash);
PHP_FUNCTION(blake3_hash_raw);
PHP_FUNCTION(blake3_keyed_hash);

extern zend_module_entry blake3_module_entry;
#define phpext_blake3_ptr &blake3_module_entry

#endif
