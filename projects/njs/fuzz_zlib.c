/*
 * Fuzzer for njs zlib module
 * Targets: zlib.deflateSync(), zlib.inflateSync(),
 *          zlib.deflateRawSync(), zlib.inflateRawSync()
 */

#include <njs.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

static njs_vm_t *g_vm = NULL;

static njs_int_t
fuzz_console_log(njs_vm_t *vm, njs_value_t *args, njs_uint_t nargs,
    njs_index_t magic, njs_value_t *retval)
{
    njs_value_undefined_set(retval);
    return NJS_OK;
}

static njs_external_t fuzz_externals[] = {
    {
        .flags = NJS_EXTERN_METHOD,
        .name.string = njs_str("log"),
        .writable = 1,
        .configurable = 1,
        .u.method = {
            .native = fuzz_console_log,
        }
    },
};

static njs_vm_t *
create_vm(void)
{
    njs_vm_t      *vm;
    njs_int_t      ret;
    njs_vm_opt_t   options;

    njs_vm_opt_init(&options);
    options.init = 1;

    vm = njs_vm_create(&options);
    if (vm == NULL) {
        return NULL;
    }

    ret = njs_vm_external_prototype(vm, fuzz_externals,
                                    sizeof(fuzz_externals) / sizeof(fuzz_externals[0]));
    if (ret < 0) {
        njs_vm_destroy(vm);
        return NULL;
    }

    return vm;
}

static void
bytes_to_hex(const uint8_t *data, size_t size, char *out, size_t max_len)
{
    size_t i;
    size_t out_idx = 0;

    for (i = 0; i < size && out_idx < max_len - 2; i++) {
        out[out_idx++] = "0123456789abcdef"[data[i] >> 4];
        out[out_idx++] = "0123456789abcdef"[data[i] & 0x0F];
    }
    out[out_idx] = '\0';
}

static void
generate_zlib_test(const uint8_t *data, size_t size, char *out, size_t out_size)
{
    uint8_t op;
    char hex_data[1024];
    int level, window_bits, mem_level;
    size_t data_offset;

    if (size < 3) {
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('test data');\n"
            "  var deflated = zlib.deflateSync(buf);\n"
            "  zlib.inflateSync(deflated);\n"
            "} catch(e) {}\n");
        return;
    }

    op = data[0] % 10;

    /* Extract compression parameters */
    level = (data[1] % 10) - 1;  /* -1 to 9 */
    window_bits = (data[2] % 7) + 9;  /* 9 to 15 */
    mem_level = (size > 3 ? data[3] % 9 : 8) + 1;  /* 1 to 9 */

    data_offset = 4;
    size_t hex_len = 0;
    if (size > data_offset) {
        hex_len = (size - data_offset) > 400 ? 400 : (size - data_offset);
    }
    bytes_to_hex(data + data_offset, hex_len, hex_data, sizeof(hex_data));

    switch (op) {
    case 0:
        /* Basic deflate then inflate */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  var deflated = zlib.deflateSync(buf);\n"
            "  var inflated = zlib.inflateSync(deflated);\n"
            "} catch(e) {}\n",
            hex_data);
        break;

    case 1:
        /* Deflate with level option */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  var deflated = zlib.deflateSync(buf, {level: %d});\n"
            "  zlib.inflateSync(deflated);\n"
            "} catch(e) {}\n",
            hex_data, level);
        break;

    case 2:
        /* Deflate with windowBits */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  var deflated = zlib.deflateSync(buf, {windowBits: %d});\n"
            "  zlib.inflateSync(deflated, {windowBits: %d});\n"
            "} catch(e) {}\n",
            hex_data, window_bits, window_bits);
        break;

    case 3:
        /* Deflate with memLevel */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  var deflated = zlib.deflateSync(buf, {memLevel: %d});\n"
            "  zlib.inflateSync(deflated);\n"
            "} catch(e) {}\n",
            hex_data, mem_level);
        break;

    case 4:
        /* Raw deflate/inflate */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  var deflated = zlib.deflateRawSync(buf);\n"
            "  zlib.inflateRawSync(deflated);\n"
            "} catch(e) {}\n",
            hex_data);
        break;

    case 5:
        /* Raw with options */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  var deflated = zlib.deflateRawSync(buf, {level: %d, windowBits: -%d});\n"
            "  zlib.inflateRawSync(deflated, {windowBits: -%d});\n"
            "} catch(e) {}\n",
            hex_data, level, window_bits, window_bits);
        break;

    case 6:
        /* Try to inflate raw fuzz data (likely invalid) */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  zlib.inflateSync(buf);\n"
            "} catch(e) {}\n",
            hex_data);
        break;

    case 7:
        /* Try to inflate raw sync with raw fuzz data */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  zlib.inflateRawSync(buf);\n"
            "} catch(e) {}\n",
            hex_data);
        break;

    case 8:
        /* Strategy options */
        {
            const char *strategies[] = {
                "zlib.constants.Z_DEFAULT_STRATEGY",
                "zlib.constants.Z_FILTERED",
                "zlib.constants.Z_HUFFMAN_ONLY",
                "zlib.constants.Z_RLE",
                "zlib.constants.Z_FIXED"
            };
            int strategy_idx = size > 4 ? data[4] % 5 : 0;

            snprintf(out, out_size,
                "var zlib = require('zlib');\n"
                "try {\n"
                "  var buf = Buffer.from('%s', 'hex');\n"
                "  var deflated = zlib.deflateSync(buf, {strategy: %s});\n"
                "  zlib.inflateSync(deflated);\n"
                "} catch(e) {}\n",
                hex_data, strategies[strategy_idx]);
        }
        break;

    case 9:
    default:
        /* Full options */
        snprintf(out, out_size,
            "var zlib = require('zlib');\n"
            "try {\n"
            "  var buf = Buffer.from('%s', 'hex');\n"
            "  var opts = {level: %d, windowBits: %d, memLevel: %d, chunkSize: %d};\n"
            "  var deflated = zlib.deflateSync(buf, opts);\n"
            "  zlib.inflateSync(deflated, {windowBits: %d, chunkSize: %d});\n"
            "} catch(e) {}\n",
            hex_data, level, window_bits, mem_level,
            64 + (size > 5 ? data[5] * 16 : 1024),
            window_bits, 64 + (size > 6 ? data[6] * 16 : 1024));
        break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    njs_int_t          ret;
    njs_opaque_value_t retval;
    njs_str_t          script;
    char          code[4096];
    u_char        *start;

    if (size == 0 || size > 8192) {
        return 0;
    }

    if (g_vm == NULL) {
        g_vm = create_vm();
        if (g_vm == NULL) {
            return 0;
        }
    }

    /* Reset VM for each iteration */
    njs_vm_destroy(g_vm);
    g_vm = create_vm();
    if (g_vm == NULL) {
        return 0;
    }

    generate_zlib_test(data, size, code, sizeof(code));

    script.start = (u_char *)code;
    script.length = strlen(code);

    start = script.start;
    ret = njs_vm_compile(g_vm, &start, start + script.length);
    if (ret != NJS_OK) {
        return 0;
    }

    ret = njs_vm_start(g_vm, njs_value_arg(&retval));

    return 0;
}
