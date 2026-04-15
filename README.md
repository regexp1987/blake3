# PHP BLAKE3 Extension

Native PHP extension for the [BLAKE3](https://blake3.io/) cryptographic hash function,
based on the official C reference implementation from the BLAKE3 team.

## Why BLAKE3?

| Feature | BLAKE3 | SHA-256 | MD5 |
|---|---|---|---|
| Speed (x86_64) | ~1.3 GB/s | ~0.3 GB/s | ~0.5 GB/s |
| Output length | Arbitrary (XOF) | Fixed 32 bytes | Fixed 16 bytes |
| Security | ✅ 256-bit | ✅ 256-bit | ❌ Broken |
| Keyed mode (MAC) | ✅ | ❌ (needs HMAC) | ❌ |
| Incremental | ✅ | ✅ | ✅ |

BLAKE3 is **4× faster than SHA-256** on modern CPUs thanks to SIMD parallelism
(AVX-512, AVX2, SSE4.1, SSE2, NEON). It's ideal for:

- **Content addressing** — file deduplication, cache keys
- **Prompt integrity** — verify AI prompts haven't drifted
- **Message authentication** — keyed hash mode replaces HMAC
- **Extendable output** — generate arbitrary-length digests

## Requirements

| Component | Minimum | Recommended |
|---|---|---|
| PHP | 8.1 | 8.4+ |
| GCC | 9+ | 12+ |
| Clang | 10+ | 15+ |
| OS | Linux / macOS / BSD | Linux x86_64 |
| Windows | Visual Studio 2019+ | Visual Studio 2022+ |

## Installation

### Via PIE (Recommended — PHP Installation & Extensions)

PIE is the modern PHP extension installer (replaces deprecated PECL). Requires PHP 8.1+.

```bash
# Install PIE (if not already available)
curl -sS https://github.com/php/pie/releases/latest/download/pie.phar -o pie.phar
chmod +x pie.phar

# Install BLAKE3 extension
php pie.phar install regexp1987/blake3

# Verify
php -r "echo blake3('hello') . PHP_EOL;"
# Output: ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f
```

PIE automatically:
- Downloads the source code
- Runs `phpize`, `./configure`, and `make`
- Installs the compiled extension to the correct PHP extension directory
- Enables the extension in `php.ini`

### From source (Linux / macOS / BSD)

If you prefer manual installation or don't have PIE:

```bash
cd ext/blake3

# Generate build system
phpize

# Configure
./configure

# Build (use all CPU cores)
make -j$(nproc)

# Run test suite
make test

# Install to PHP extension directory
sudo make install

# Enable the extension
echo "extension=blake3.so" | sudo tee /etc/php/8.4/mods-available/blake3.ini
sudo phpenmod blake3

# Verify
php -r "echo blake3('hello') . PHP_EOL;"
# Output: ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f
```

### Windows (Visual Studio)

```bat
cd ext\blake3
phpize
configure --enable-blake3
nmake
php -r "echo blake3('hello');"
```

Copy `Release\php_blake3.dll` to your PHP `ext` directory and add
`extension=php_blake3.dll` to `php.ini`.

### Docker

```dockerfile
FROM php:8.4-cli
COPY ext/blake3 /usr/local/src/blake3
RUN cd /usr/local/src/blake3 \
  && phpize \
  && ./configure \
  && make -j$(nproc) \
  && make install \
  && docker-php-ext-enable blake3
```

## API Reference

### Functions

#### `blake3(string $data, int $output_length = 32, ?string $key = null, bool $raw_output = false): string`

One-shot BLAKE3 hash. Returns lowercase hex by default.

```php
// Default 256-bit hash
$hash = blake3("hello world");
// => "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"

// Custom output length (extendable output)
$hash4 = blake3("hello", 4);
// => "f9406799"

// Raw binary output
$raw = blake3("hello", 32, null, true);
// => "\xf9\x40\x67\x99..." (32 bytes)

// Keyed mode (MAC)
$key = random_bytes(32);
$mac = blake3("message", 32, $key);
```

**Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `$data` | string | required | Input data to hash |
| `$output_length` | int | 32 | Output length in bytes (1–2^64−1, limited by available memory) |
| `$key` | string\|null | null | 32-byte key for keyed-hash (MAC) mode |
| `$raw_output` | bool | false | If true, return raw bytes instead of hex |

**Returns:** `string` — lowercase hex digest, or raw bytes if `$raw_output = true`

**Throws:** `ValueError` if `$key` is not exactly 32 bytes, or `$output_length < 1`

---

#### `blake3_file(string $filename, int $output_length = 32, ?string $key = null, bool $raw_output = false): string`

Hash a file using streaming (8 KB chunks). Memory-efficient for large files.

```php
$hash = blake3_file("/var/log/syslog");
// => 64-char hex string

// Streaming — works for GB-sized files without loading into memory
$raw = blake3_file("/var/backups/db.sql.gz", 32, null, true);

// Keyed file hash (MAC)
$key = random_bytes(32);
$mac = blake3_file("/var/backups/db.sql.gz", 32, $key);
```

**Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `$filename` | string | required | Path to the file |
| `$output_length` | int | 32 | Output length in bytes |
| `$key` | string\|null | null | 32-byte key for keyed-hash (MAC) mode |
| `$raw_output` | bool | false | If true, return raw bytes |

**Returns:** `string` — hex digest or raw bytes; `false` on read error

**Throws:** `ValueError` if `$filename` is empty, `$output_length < 1`, or `$key` is not exactly 32 bytes

---

#### `blake3_hash(string $data, int $output_length = 32): string`

Convenience alias for `blake3($data, $output_length, null, false)`.
Returns hex string. Kept for backward compatibility.

---

#### `blake3_hash_raw(string $data, int $output_length = 32): string`

Convenience alias for `blake3($data, $output_length, null, true)`.
Returns raw binary string.

---

#### `blake3_keyed_hash(string $data, string $key, int $output_length = 32): string`

Convenience alias for `blake3($data, $output_length, $key, false)`.
Keyed-hash (MAC) mode. `$key` must be exactly 32 bytes.

---

#### `blake3_init(?string $key = null): Blake3Context`

Initialise an incremental hashing context.

```php
$ctx = blake3_init();
blake3_update($ctx, "chunk1");
blake3_update($ctx, "chunk2");
$hash = blake3_final($ctx);
```

With key:
```php
$key = random_bytes(32);
$ctx = blake3_init($key);
blake3_update($ctx, $data);
$mac = blake3_final($ctx);
```

**Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `$key` | string\|null | null | 32-byte key for keyed-hash mode |

**Returns:** `Blake3Context` — opaque handle for incremental hashing

**Throws:** `ValueError` if `$key` is provided but not exactly 32 bytes

---

#### `blake3_update(Blake3Context $ctx, string $data): void`

Append data to an incremental hash context.

```php
$ctx = blake3_init();
$fp = fopen("large_file.bin", "r");
while (($chunk = fread($fp, 8192)) !== false) {
    blake3_update($ctx, $chunk);
}
fclose($fp);
$hash = blake3_final($ctx);
```

**Throws:** `ValueError` if `$ctx` is not a valid `Blake3Context`

---

#### `blake3_final(Blake3Context $ctx, bool $raw_output = false): string`

Finalise the incremental hash and return the digest.

**Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `$ctx` | Blake3Context | required | The hashing context (consumed — cannot reuse) |
| `$raw_output` | bool | false | If true, return raw bytes |

**Returns:** `string` — hex digest or raw bytes

**Note:** After calling `blake3_final()`, the context is consumed. Use `blake3_reset()` to
reinitialise it, or create a new context with `blake3_init()` for subsequent hashes.

---

#### `blake3_xof(string $data, int $output_length, ?string $key = null, bool $raw_output = false): string`

Extendable Output Function (XOF). Equivalent to `blake3()` with an explicit, required output length.

```php
// Generate a 64-byte digest (hex)
$hash64 = blake3_xof("data", 64);

// Raw bytes
$raw = blake3_xof("data", 64, null, true);

// Keyed
$key = random_bytes(32);
$mac = blake3_xof("data", 64, $key);
```

**Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `$data` | string | required | Input data |
| `$output_length` | int | required | Output length in bytes (must be ≥ 1) |
| `$key` | string\|null | null | 32-byte key for keyed-hash (MAC) mode |
| `$raw_output` | bool | false | If true, return raw bytes |

---

---

#### `blake3_derive_key(string $context, string $key_material, int $output_length = 32, bool $raw_output = false): string`

Key Derivation Function (KDF) mode. Derives a key from a context string and key material.
The context string must be unique to the application and protocol version — it is not secret.

```php
$derivedKey = blake3_derive_key('my-app v1 session-key', $masterSecret);
// => 64-char hex string (32 bytes)

// Raw bytes, custom length
$rawKey = blake3_derive_key('my-app v1 encryption-key', $masterSecret, 32, true);
```

**Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `$context` | string | required | Non-empty application context string (e.g. `"my-app v1 purpose"`) |
| `$key_material` | string | required | Non-empty secret key material |
| `$output_length` | int | 32 | Output length in bytes |
| `$raw_output` | bool | false | If true, return raw bytes |

**Returns:** `string` — hex digest or raw bytes

**Throws:** `ValueError` if `$context` or `$key_material` is empty, or `$output_length < 1`

---

#### `blake3_version(): string`

Returns the BLAKE3 library version string.

```php
echo blake3_version();
// => "1.0.0"
```

### Class: `Blake3Context`

Opaque resource handle returned by `blake3_init()`. Cannot be instantiated directly.

```php
$ctx = blake3_init();
// $ctx is of type Blake3Context (internal resource)
```

### Constants

| Constant | Value | Description |
|---|---|---|
| `BLAKE3_OUT_LEN` | 32 | Default output length (bytes) |
| `BLAKE3_KEY_LEN` | 32 | Key length for MAC mode (bytes) |
| `BLAKE3_BLOCK_LEN` | 64 | Block size (bytes) |
| `BLAKE3_MAX_DEPTH` | 54 | Maximum tree depth |
| `BLAKE3_MAX_OUTPUT` | 67108864 | Maximum output length enforced by this extension (64 MB) |

## Benchmark

Compare BLAKE3 with PHP built-in hash functions:

```php
$data = str_repeat("x", 1024 * 1024); // 1 MB

$start = microtime(true);
for ($i = 0; $i < 100; ++$i) {
    blake3($data);
}
printf("BLAKE3:  %.2f ms/op\n", (microtime(true) - $start) / 100 * 1000);

$start = microtime(true);
for ($i = 0; $i < 100; ++$i) {
    hash('sha256', $data);
}
printf("SHA-256: %.2f ms/op\n", (microtime(true) - $start) / 100 * 1000);
```

Typical results (Intel Core i7, Linux x86_64):
```
BLAKE3:  0.78 ms/op
SHA-256: 3.21 ms/op
MD5:     1.95 ms/op
```

## Test Vectors

```php
// BLAKE3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
assert(blake3("") === 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262');

// BLAKE3("hello") = ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f
assert(blake3("hello") === 'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f');
```

## Known Limitations

- **Maximum output length**: limited by available memory (Zend string allocation).
  Practical limit is ~2GB on 32-bit systems, no practical limit on 64-bit.
- **Thread safety**: the extension is ZTS-compatible but incremental contexts
  (`Blake3Context`) are not thread-safe — don't share across threads.
- **Windows SIMD**: assembly files are included but require MASM/NASM.
  Falls back to portable C if assembly tooling is unavailable.

## License

MIT License — see [LICENSE](LICENSE).

The bundled BLAKE3 C reference implementation is dual-licensed under
[CC0](https://creativecommons.org/publicdomain/zero/1.0/) and the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Credits

- **BLAKE3** designed by [Jean-Philippe Aumasson](https://aumas.sons.io/) and
  [Samuel Neves](https://web.mat.upc.edu/samuel.neves/)
- **C reference implementation** by the [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3)
- **PHP extension** by [Andrea Pievaioli](https://github.com/regexp1987)


