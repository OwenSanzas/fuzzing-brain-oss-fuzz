/*
 * njs webcrypto fuzzer
 *
 * Target functions:
 *   - njs_ext_generate_key
 *   - njs_ext_import_key
 *   - njs_ext_cipher (encrypt/decrypt)
 *   - njs_ext_derive (deriveKey/deriveBits)
 *
 * Strategy: Use fuzz input bytes to select crypto operations and parameters,
 * then generate valid JavaScript code that exercises the webcrypto API.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "njs.h"

/* Algorithm names */
static const char *algorithms[] = {
    "AES-GCM",
    "AES-CTR",
    "AES-CBC",
    "HMAC",
    "PBKDF2",
    "HKDF",
    "ECDSA",
    "ECDH",
    "RSA-OAEP",
    "RSASSA-PKCS1-v1_5",
    "RSA-PSS"
};
#define NUM_ALGORITHMS (sizeof(algorithms) / sizeof(algorithms[0]))

/* Hash algorithms */
static const char *hashes[] = {
    "SHA-1",
    "SHA-256",
    "SHA-384",
    "SHA-512"
};
#define NUM_HASHES (sizeof(hashes) / sizeof(hashes[0]))

/* EC curves */
static const char *curves[] = {
    "P-256",
    "P-384",
    "P-521"
};
#define NUM_CURVES (sizeof(curves) / sizeof(curves[0]))

/* AES key lengths */
static const int aes_lengths[] = { 128, 192, 256 };
#define NUM_AES_LENGTHS (sizeof(aes_lengths) / sizeof(aes_lengths[0]))

/* RSA modulus lengths */
static const int rsa_lengths[] = { 1024, 2048, 4096 };
#define NUM_RSA_LENGTHS (sizeof(rsa_lengths) / sizeof(rsa_lengths[0]))

/* Operations */
typedef enum {
    OP_GENERATE_KEY = 0,
    OP_IMPORT_KEY,
    OP_ENCRYPT_DECRYPT,
    OP_DERIVE,
    OP_MAX
} crypto_op_t;


static void generate_aes_script(char *buf, size_t bufsize,
                                const uint8_t *data, size_t size,
                                int alg_idx, int op)
{
    const char *alg = algorithms[alg_idx];
    int key_len = aes_lengths[size > 0 ? data[0] % NUM_AES_LENGTHS : 0];
    int hash_idx = size > 1 ? data[1] % NUM_HASHES : 0;

    /* Generate IV from fuzz data */
    char iv_bytes[64] = {0};
    size_t iv_len = (alg_idx == 1) ? 16 : 12; /* AES-CTR uses 16, others 12 */
    for (size_t i = 0; i < iv_len && i + 2 < size; i++) {
        snprintf(iv_bytes + strlen(iv_bytes), sizeof(iv_bytes) - strlen(iv_bytes),
                 "%s%d", i > 0 ? "," : "", data[i + 2]);
    }
    if (strlen(iv_bytes) == 0) {
        strcpy(iv_bytes, "0,0,0,0,0,0,0,0,0,0,0,0");
    }

    /* Generate data to encrypt from fuzz input */
    char data_bytes[256] = {0};
    size_t data_start = 2 + iv_len;
    for (size_t i = 0; i < 32 && data_start + i < size; i++) {
        snprintf(data_bytes + strlen(data_bytes), sizeof(data_bytes) - strlen(data_bytes),
                 "%s%d", i > 0 ? "," : "", data[data_start + i]);
    }
    if (strlen(data_bytes) == 0) {
        strcpy(data_bytes, "72,101,108,108,111"); /* "Hello" */
    }

    if (op == OP_GENERATE_KEY || op == OP_ENCRYPT_DECRYPT) {
        snprintf(buf, bufsize,
            "(async () => {\n"
            "  try {\n"
            "    const key = await crypto.subtle.generateKey(\n"
            "      { name: '%s', length: %d },\n"
            "      true,\n"
            "      ['encrypt', 'decrypt']\n"
            "    );\n"
            "    const data = new Uint8Array([%s]);\n"
            "    const iv = new Uint8Array([%s]);\n"
            "    const encrypted = await crypto.subtle.encrypt(\n"
            "      { name: '%s', iv: iv%s },\n"
            "      key, data\n"
            "    );\n"
            "    const decrypted = await crypto.subtle.decrypt(\n"
            "      { name: '%s', iv: iv%s },\n"
            "      key, encrypted\n"
            "    );\n"
            "  } catch (e) {}\n"
            "})();\n",
            alg, key_len, data_bytes, iv_bytes,
            alg, (alg_idx == 0) ? ", tagLength: 128" : "",
            alg, (alg_idx == 0) ? ", tagLength: 128" : ""
        );
    } else {
        snprintf(buf, bufsize,
            "(async () => {\n"
            "  try {\n"
            "    const key = await crypto.subtle.generateKey(\n"
            "      { name: '%s', length: %d },\n"
            "      true,\n"
            "      ['encrypt', 'decrypt']\n"
            "    );\n"
            "  } catch (e) {}\n"
            "})();\n",
            alg, key_len
        );
    }
}


static void generate_hmac_script(char *buf, size_t bufsize,
                                 const uint8_t *data, size_t size)
{
    int hash_idx = size > 0 ? data[0] % NUM_HASHES : 0;
    const char *hash = hashes[hash_idx];

    /* Generate data to sign from fuzz input */
    char data_bytes[256] = {0};
    for (size_t i = 0; i < 32 && i + 1 < size; i++) {
        snprintf(data_bytes + strlen(data_bytes), sizeof(data_bytes) - strlen(data_bytes),
                 "%s%d", i > 0 ? "," : "", data[i + 1]);
    }
    if (strlen(data_bytes) == 0) {
        strcpy(data_bytes, "72,101,108,108,111");
    }

    snprintf(buf, bufsize,
        "(async () => {\n"
        "  try {\n"
        "    const key = await crypto.subtle.generateKey(\n"
        "      { name: 'HMAC', hash: '%s' },\n"
        "      true,\n"
        "      ['sign', 'verify']\n"
        "    );\n"
        "    const data = new Uint8Array([%s]);\n"
        "    const sig = await crypto.subtle.sign('HMAC', key, data);\n"
        "    await crypto.subtle.verify('HMAC', key, sig, data);\n"
        "  } catch (e) {}\n"
        "})();\n",
        hash, data_bytes
    );
}


static void generate_pbkdf2_script(char *buf, size_t bufsize,
                                   const uint8_t *data, size_t size)
{
    int hash_idx = size > 0 ? data[0] % NUM_HASHES : 0;
    const char *hash = hashes[hash_idx];
    int iterations = size > 1 ? (data[1] % 100) + 1 : 10;

    /* Generate password from fuzz input */
    char pwd_bytes[128] = {0};
    for (size_t i = 0; i < 16 && i + 2 < size; i++) {
        snprintf(pwd_bytes + strlen(pwd_bytes), sizeof(pwd_bytes) - strlen(pwd_bytes),
                 "%s%d", i > 0 ? "," : "", data[i + 2]);
    }
    if (strlen(pwd_bytes) == 0) {
        strcpy(pwd_bytes, "112,97,115,115"); /* "pass" */
    }

    /* Generate salt from fuzz input */
    char salt_bytes[128] = {0};
    size_t salt_start = 18;
    for (size_t i = 0; i < 16 && salt_start + i < size; i++) {
        snprintf(salt_bytes + strlen(salt_bytes), sizeof(salt_bytes) - strlen(salt_bytes),
                 "%s%d", i > 0 ? "," : "", data[salt_start + i]);
    }
    if (strlen(salt_bytes) == 0) {
        strcpy(salt_bytes, "115,97,108,116"); /* "salt" */
    }

    snprintf(buf, bufsize,
        "(async () => {\n"
        "  try {\n"
        "    const keyMaterial = await crypto.subtle.importKey(\n"
        "      'raw',\n"
        "      new Uint8Array([%s]),\n"
        "      'PBKDF2',\n"
        "      false,\n"
        "      ['deriveBits', 'deriveKey']\n"
        "    );\n"
        "    const key = await crypto.subtle.deriveKey(\n"
        "      {\n"
        "        name: 'PBKDF2',\n"
        "        salt: new Uint8Array([%s]),\n"
        "        iterations: %d,\n"
        "        hash: '%s'\n"
        "      },\n"
        "      keyMaterial,\n"
        "      { name: 'AES-GCM', length: 256 },\n"
        "      true,\n"
        "      ['encrypt', 'decrypt']\n"
        "    );\n"
        "    const bits = await crypto.subtle.deriveBits(\n"
        "      {\n"
        "        name: 'PBKDF2',\n"
        "        salt: new Uint8Array([%s]),\n"
        "        iterations: %d,\n"
        "        hash: '%s'\n"
        "      },\n"
        "      keyMaterial,\n"
        "      256\n"
        "    );\n"
        "  } catch (e) {}\n"
        "})();\n",
        pwd_bytes, salt_bytes, iterations, hash,
        salt_bytes, iterations, hash
    );
}


static void generate_hkdf_script(char *buf, size_t bufsize,
                                 const uint8_t *data, size_t size)
{
    int hash_idx = size > 0 ? data[0] % NUM_HASHES : 0;
    const char *hash = hashes[hash_idx];

    /* Generate key material from fuzz input */
    char key_bytes[128] = {0};
    for (size_t i = 0; i < 16 && i + 1 < size; i++) {
        snprintf(key_bytes + strlen(key_bytes), sizeof(key_bytes) - strlen(key_bytes),
                 "%s%d", i > 0 ? "," : "", data[i + 1]);
    }
    if (strlen(key_bytes) == 0) {
        strcpy(key_bytes, "107,101,121"); /* "key" */
    }

    /* Generate salt and info from fuzz input */
    char salt_bytes[64] = {0};
    char info_bytes[64] = {0};
    size_t salt_start = 17;
    size_t info_start = 33;

    for (size_t i = 0; i < 16 && salt_start + i < size; i++) {
        snprintf(salt_bytes + strlen(salt_bytes), sizeof(salt_bytes) - strlen(salt_bytes),
                 "%s%d", i > 0 ? "," : "", data[salt_start + i]);
    }
    if (strlen(salt_bytes) == 0) strcpy(salt_bytes, "115,97,108,116");

    for (size_t i = 0; i < 16 && info_start + i < size; i++) {
        snprintf(info_bytes + strlen(info_bytes), sizeof(info_bytes) - strlen(info_bytes),
                 "%s%d", i > 0 ? "," : "", data[info_start + i]);
    }
    if (strlen(info_bytes) == 0) strcpy(info_bytes, "105,110,102,111");

    snprintf(buf, bufsize,
        "(async () => {\n"
        "  try {\n"
        "    const keyMaterial = await crypto.subtle.importKey(\n"
        "      'raw',\n"
        "      new Uint8Array([%s]),\n"
        "      'HKDF',\n"
        "      false,\n"
        "      ['deriveBits', 'deriveKey']\n"
        "    );\n"
        "    const key = await crypto.subtle.deriveKey(\n"
        "      {\n"
        "        name: 'HKDF',\n"
        "        hash: '%s',\n"
        "        salt: new Uint8Array([%s]),\n"
        "        info: new Uint8Array([%s])\n"
        "      },\n"
        "      keyMaterial,\n"
        "      { name: 'AES-GCM', length: 256 },\n"
        "      true,\n"
        "      ['encrypt', 'decrypt']\n"
        "    );\n"
        "  } catch (e) {}\n"
        "})();\n",
        key_bytes, hash, salt_bytes, info_bytes
    );
}


static void generate_ecdh_script(char *buf, size_t bufsize,
                                 const uint8_t *data, size_t size)
{
    int curve_idx = size > 0 ? data[0] % NUM_CURVES : 0;
    const char *curve = curves[curve_idx];

    snprintf(buf, bufsize,
        "(async () => {\n"
        "  try {\n"
        "    const keyPair1 = await crypto.subtle.generateKey(\n"
        "      { name: 'ECDH', namedCurve: '%s' },\n"
        "      true,\n"
        "      ['deriveBits', 'deriveKey']\n"
        "    );\n"
        "    const keyPair2 = await crypto.subtle.generateKey(\n"
        "      { name: 'ECDH', namedCurve: '%s' },\n"
        "      true,\n"
        "      ['deriveBits', 'deriveKey']\n"
        "    );\n"
        "    const sharedKey = await crypto.subtle.deriveKey(\n"
        "      { name: 'ECDH', public: keyPair2.publicKey },\n"
        "      keyPair1.privateKey,\n"
        "      { name: 'AES-GCM', length: 256 },\n"
        "      true,\n"
        "      ['encrypt', 'decrypt']\n"
        "    );\n"
        "    const bits = await crypto.subtle.deriveBits(\n"
        "      { name: 'ECDH', public: keyPair2.publicKey },\n"
        "      keyPair1.privateKey,\n"
        "      256\n"
        "    );\n"
        "  } catch (e) {}\n"
        "})();\n",
        curve, curve
    );
}


static void generate_ecdsa_script(char *buf, size_t bufsize,
                                  const uint8_t *data, size_t size)
{
    int curve_idx = size > 0 ? data[0] % NUM_CURVES : 0;
    int hash_idx = size > 1 ? data[1] % NUM_HASHES : 0;
    const char *curve = curves[curve_idx];
    const char *hash = hashes[hash_idx];

    /* Generate data to sign from fuzz input */
    char data_bytes[256] = {0};
    for (size_t i = 0; i < 32 && i + 2 < size; i++) {
        snprintf(data_bytes + strlen(data_bytes), sizeof(data_bytes) - strlen(data_bytes),
                 "%s%d", i > 0 ? "," : "", data[i + 2]);
    }
    if (strlen(data_bytes) == 0) {
        strcpy(data_bytes, "72,101,108,108,111");
    }

    snprintf(buf, bufsize,
        "(async () => {\n"
        "  try {\n"
        "    const keyPair = await crypto.subtle.generateKey(\n"
        "      { name: 'ECDSA', namedCurve: '%s' },\n"
        "      true,\n"
        "      ['sign', 'verify']\n"
        "    );\n"
        "    const data = new Uint8Array([%s]);\n"
        "    const sig = await crypto.subtle.sign(\n"
        "      { name: 'ECDSA', hash: '%s' },\n"
        "      keyPair.privateKey,\n"
        "      data\n"
        "    );\n"
        "    await crypto.subtle.verify(\n"
        "      { name: 'ECDSA', hash: '%s' },\n"
        "      keyPair.publicKey,\n"
        "      sig,\n"
        "      data\n"
        "    );\n"
        "  } catch (e) {}\n"
        "})();\n",
        curve, data_bytes, hash, hash
    );
}


static void generate_import_raw_script(char *buf, size_t bufsize,
                                       const uint8_t *data, size_t size)
{
    int hash_idx = size > 0 ? data[0] % NUM_HASHES : 0;
    const char *hash = hashes[hash_idx];

    /* Generate key bytes from fuzz input - must be valid AES key length */
    char key_bytes[256] = {0};
    size_t key_len = 32; /* AES-256 */
    for (size_t i = 0; i < key_len; i++) {
        size_t idx = (i + 1) < size ? i + 1 : 0;
        snprintf(key_bytes + strlen(key_bytes), sizeof(key_bytes) - strlen(key_bytes),
                 "%s%d", i > 0 ? "," : "", data[idx] % 256);
    }

    snprintf(buf, bufsize,
        "(async () => {\n"
        "  try {\n"
        "    const rawKey = new Uint8Array([%s]);\n"
        "    const key = await crypto.subtle.importKey(\n"
        "      'raw',\n"
        "      rawKey,\n"
        "      { name: 'AES-GCM' },\n"
        "      true,\n"
        "      ['encrypt', 'decrypt']\n"
        "    );\n"
        "    const hmacKey = await crypto.subtle.importKey(\n"
        "      'raw',\n"
        "      rawKey,\n"
        "      { name: 'HMAC', hash: '%s' },\n"
        "      true,\n"
        "      ['sign', 'verify']\n"
        "    );\n"
        "  } catch (e) {}\n"
        "})();\n",
        key_bytes, hash
    );
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    njs_vm_t            *vm;
    njs_vm_opt_t         opts;
    njs_int_t            ret;
    njs_opaque_value_t   retval;
    char                 script[4096];
    u_char              *start, *end;

    if (size == 0) {
        return 0;
    }

    /* Select which crypto operation to test based on first byte */
    int op_selector = data[0] % 8;
    const uint8_t *op_data = size > 1 ? data + 1 : data;
    size_t op_size = size > 1 ? size - 1 : 0;

    switch (op_selector) {
    case 0: /* AES-GCM */
        generate_aes_script(script, sizeof(script), op_data, op_size, 0, OP_ENCRYPT_DECRYPT);
        break;
    case 1: /* AES-CTR */
        generate_aes_script(script, sizeof(script), op_data, op_size, 1, OP_ENCRYPT_DECRYPT);
        break;
    case 2: /* AES-CBC */
        generate_aes_script(script, sizeof(script), op_data, op_size, 2, OP_ENCRYPT_DECRYPT);
        break;
    case 3: /* HMAC */
        generate_hmac_script(script, sizeof(script), op_data, op_size);
        break;
    case 4: /* PBKDF2 */
        generate_pbkdf2_script(script, sizeof(script), op_data, op_size);
        break;
    case 5: /* HKDF */
        generate_hkdf_script(script, sizeof(script), op_data, op_size);
        break;
    case 6: /* ECDH + ECDSA */
        if (op_size > 0 && op_data[0] % 2 == 0) {
            generate_ecdh_script(script, sizeof(script), op_data, op_size);
        } else {
            generate_ecdsa_script(script, sizeof(script), op_data, op_size);
        }
        break;
    case 7: /* Import key */
        generate_import_raw_script(script, sizeof(script), op_data, op_size);
        break;
    default:
        generate_aes_script(script, sizeof(script), op_data, op_size, 0, OP_GENERATE_KEY);
        break;
    }

    njs_vm_opt_init(&opts);
    opts.init = 1;
    opts.sandbox = 1;

    vm = njs_vm_create(&opts);
    if (vm == NULL) {
        return 0;
    }

    start = (u_char *) script;
    end = start + strlen(script);

    ret = njs_vm_compile(vm, &start, end);
    if (ret == NJS_OK) {
        (void) njs_vm_start(vm, njs_value_arg(&retval));

        /* Execute pending jobs (promises) */
        while (njs_vm_pending(vm)) {
            (void) njs_vm_execute_pending_job(vm);
        }
    }

    njs_vm_destroy(vm);

    return 0;
}
