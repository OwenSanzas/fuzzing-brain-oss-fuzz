/*
 * Fuzzer for njs XML module (libxml2 based)
 * Targets: xml.parse(), xml.c14n(), xml.exclusiveC14n(), xml.serialize()
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
generate_xml_test(const uint8_t *data, size_t size, char *out, size_t out_size)
{
    uint8_t op;
    size_t content_len;
    char tag_name[32];
    char attr_name[32];
    char content[256];
    int i;

    if (size < 2) {
        snprintf(out, out_size, "var xml = require('xml'); try { xml.parse('<root/>'); } catch(e) {}");
        return;
    }

    op = data[0] % 8;

    /* Generate tag/attr names from fuzz data */
    for (i = 0; i < 8 && i + 1 < (int)size; i++) {
        tag_name[i] = 'a' + (data[i + 1] % 26);
    }
    tag_name[i] = '\0';
    if (i == 0) strcpy(tag_name, "tag");

    for (i = 0; i < 8 && i + 9 < (int)size; i++) {
        attr_name[i] = 'a' + (data[i + 9] % 26);
    }
    attr_name[i] = '\0';
    if (i == 0) strcpy(attr_name, "attr");

    /* Generate content - escape special chars */
    content_len = size > 17 ? (size - 17 > 200 ? 200 : size - 17) : 0;
    for (i = 0; i < (int)content_len; i++) {
        uint8_t c = data[17 + i];
        if (c == '<' || c == '>' || c == '&' || c == '"' || c == '\'' || c < 32) {
            content[i] = 'x';
        } else {
            content[i] = c;
        }
    }
    content[content_len] = '\0';

    switch (op) {
    case 0:
        /* Simple XML parsing */
        snprintf(out, out_size,
            "var xml = require('xml');\n"
            "try {\n"
            "  var doc = xml.parse('<%s>%s</%s>');\n"
            "  if (doc && doc.$root) { var r = doc.$root.$name; }\n"
            "} catch(e) {}\n",
            tag_name, content, tag_name);
        break;

    case 1:
        /* XML with attributes */
        snprintf(out, out_size,
            "var xml = require('xml');\n"
            "try {\n"
            "  var doc = xml.parse('<%s %s=\"%s\">%s</%s>');\n"
            "  if (doc && doc.$root && doc.$root.$attrs) {\n"
            "    var attrs = doc.$root.$attrs;\n"
            "  }\n"
            "} catch(e) {}\n",
            tag_name, attr_name, content, content, tag_name);
        break;

    case 2:
        /* Nested XML */
        snprintf(out, out_size,
            "var xml = require('xml');\n"
            "try {\n"
            "  var doc = xml.parse('<root><%s><%s>%s</%s></%s></root>');\n"
            "  if (doc && doc.$root) {\n"
            "    var tags = doc.$root.$tags;\n"
            "  }\n"
            "} catch(e) {}\n",
            tag_name, attr_name, content, attr_name, tag_name);
        break;

    case 3:
        /* XML with namespace */
        snprintf(out, out_size,
            "var xml = require('xml');\n"
            "try {\n"
            "  var doc = xml.parse('<ns:%s xmlns:ns=\"http://example.com\">%s</ns:%s>');\n"
            "  if (doc && doc.$root) { var ns = doc.$root.$ns; }\n"
            "} catch(e) {}\n",
            tag_name, content, tag_name);
        break;

    case 4:
        /* XML canonicalization */
        snprintf(out, out_size,
            "var xml = require('xml');\n"
            "try {\n"
            "  var doc = xml.parse('<%s>%s</%s>');\n"
            "  if (doc) { var c = xml.c14n(doc); }\n"
            "} catch(e) {}\n",
            tag_name, content, tag_name);
        break;

    case 5:
        /* Exclusive canonicalization */
        snprintf(out, out_size,
            "var xml = require('xml');\n"
            "try {\n"
            "  var doc = xml.parse('<%s xmlns=\"http://test\">%s</%s>');\n"
            "  if (doc) { var c = xml.exclusiveC14n(doc); }\n"
            "} catch(e) {}\n",
            tag_name, content, tag_name);
        break;

    case 6:
        /* XML serialization */
        snprintf(out, out_size,
            "var xml = require('xml');\n"
            "try {\n"
            "  var doc = xml.parse('<%s %s=\"val\">%s</%s>');\n"
            "  if (doc) { var s = xml.serializeToString(doc); }\n"
            "} catch(e) {}\n",
            tag_name, attr_name, content, tag_name);
        break;

    case 7:
    default:
        /* Raw XML from fuzz data */
        {
            char raw_xml[512];
            size_t raw_len = size > 400 ? 400 : size;

            /* Escape for JavaScript string */
            int j = 0;
            for (i = 0; i < (int)raw_len && j < 480; i++) {
                uint8_t c = data[i];
                if (c == '\\') {
                    raw_xml[j++] = '\\';
                    raw_xml[j++] = '\\';
                } else if (c == '\'') {
                    raw_xml[j++] = '\\';
                    raw_xml[j++] = '\'';
                } else if (c == '\n') {
                    raw_xml[j++] = '\\';
                    raw_xml[j++] = 'n';
                } else if (c == '\r') {
                    raw_xml[j++] = '\\';
                    raw_xml[j++] = 'r';
                } else if (c >= 32 && c < 127) {
                    raw_xml[j++] = c;
                } else {
                    raw_xml[j++] = ' ';
                }
            }
            raw_xml[j] = '\0';

            snprintf(out, out_size,
                "var xml = require('xml');\n"
                "try { xml.parse('%s'); } catch(e) {}\n",
                raw_xml);
        }
        break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    njs_int_t          ret;
    njs_opaque_value_t retval;
    njs_str_t          script;
    char          code[2048];
    u_char        *start;

    if (size == 0 || size > 4096) {
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

    generate_xml_test(data, size, code, sizeof(code));

    script.start = (u_char *)code;
    script.length = strlen(code);

    start = script.start;
    ret = njs_vm_compile(g_vm, &start, start + script.length);
    if (ret != NJS_OK) {
        return 0;
    }

    ret = njs_vm_start(g_vm, njs_value_arg(&retval));

    /* Handle pending promises */
    while (njs_vm_pending(g_vm)) {
        ret = njs_vm_execute_pending_job(g_vm);
        if (ret != NJS_OK) {
            break;
        }
    }

    return 0;
}
