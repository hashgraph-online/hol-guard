#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PROBE_LOG_PATH
#error PROBE_LOG_PATH must bind the private probe capture log
#endif

struct response {
    const char *id;
    const char *stdout_text;
    const char *stderr_text;
    int code;
};

static const struct response cases[] = {
    {"negative-empty", "", "", 0},
    {"negative-malformed", "not-json\n", "", 0},
    {"negative-missing-decision", "{\"policy_action\":\"allow\"}\n", "", 0},
    {"negative-missing-proof", "{\"decision\":\"allow\",\"model_output_action\":\"allow_original\"}\n", "", 0},
    {"negative-mismatch-proof", "{\"decision\":\"allow\",\"model_output_action\":\"allow_original\","
     "\"reviewed_output_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"}\n", "", 0},
    {"negative-nonzero-allow", "{\"decision\":\"allow\"}\n", "cli failed\n", 2},
    {"negative-observe", "{\"decision\":\"allow\",\"observe_mode\":true}\n", "", 0},
};

static char *base64(const unsigned char *bytes, size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *encoded = malloc(4 * ((length + 2) / 3) + 1);
    if (encoded == NULL) return NULL;
    size_t output = 0;
    for (size_t offset = 0; offset < length; offset += 3) {
        unsigned int value = (unsigned int)bytes[offset] << 16;
        if (offset + 1 < length) value |= (unsigned int)bytes[offset + 1] << 8;
        if (offset + 2 < length) value |= bytes[offset + 2];
        encoded[output++] = alphabet[(value >> 18) & 63];
        encoded[output++] = alphabet[(value >> 12) & 63];
        encoded[output++] = offset + 1 < length ? alphabet[(value >> 6) & 63] : '=';
        encoded[output++] = offset + 2 < length ? alphabet[value & 63] : '=';
    }
    encoded[output] = '\0';
    return encoded;
}

int main(int argc, char **argv) {
    unsigned char input[32769];
    size_t length = fread(input, 1, sizeof(input) - 1, stdin);
    if (ferror(stdin) || fgetc(stdin) != EOF) return 125;
    input[length] = '\0';
    int recovery = argc > 2 && strcmp(argv[1], "daemon") == 0 && strcmp(argv[2], "recover") == 0;
    struct response response = {"unknown", recovery ? "" : "not-json\n", "", recovery ? 1 : 0};
    if (!recovery) {
        for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
            char quoted_id[80];
            snprintf(quoted_id, sizeof(quoted_id), "\"%s\"", cases[index].id);
            if (strstr((const char *)input, quoted_id) != NULL) {
                response = cases[index];
                break;
            }
        }
    }
    char *stdin_b64 = base64(input, length);
    char *stdout_b64 = base64((const unsigned char *)response.stdout_text, strlen(response.stdout_text));
    char *stderr_b64 = base64((const unsigned char *)response.stderr_text, strlen(response.stderr_text));
    if (stdin_b64 == NULL || stdout_b64 == NULL || stderr_b64 == NULL) {
        free(stdin_b64);
        free(stdout_b64);
        free(stderr_b64);
        return 125;
    }
    FILE *log = fopen(PROBE_LOG_PATH, "ab");
    if (log == NULL) {
        free(stdin_b64);
        free(stdout_b64);
        free(stderr_b64);
        return 125;
    }
    int written = fprintf(log, "{\"case_id\":\"%s\",\"invocation_kind\":\"%s\",\"returncode\":%d,"
                          "\"stdin_b64\":\"%s\",\"stdout_b64\":\"%s\",\"stderr_b64\":\"%s\"}\n",
                          response.id, recovery ? "recovery" : "hook", response.code,
                          stdin_b64, stdout_b64, stderr_b64);
    free(stdin_b64);
    free(stdout_b64);
    free(stderr_b64);
    int closed = fclose(log);
    if (written < 0 || closed != 0) return 125;
    if (fputs(response.stdout_text, stdout) == EOF || fputs(response.stderr_text, stderr) == EOF) return 125;
    return response.code;
}
