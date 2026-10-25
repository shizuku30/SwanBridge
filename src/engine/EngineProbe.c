/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "Engine.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

static void log_line(void *context, const char *line) { fprintf(stderr, "%s\n", line); }

int main(int argc, char **argv)
{
    if (argc != 4 && !(argc == 5 && !strcmp(argv[4], "--repeat"))) { fprintf(stderr, "Usage: SwanBridge.EngineProbe.exe server local-id remote-id [--repeat] (PSK on stdin)\n"); return 1; }
    char secret[1025];
    if (!fgets(secret, sizeof(secret), stdin)) { return 1; }
    size_t length = strcspn(secret, "\r\n");
    sb_config config = { .size = sizeof(config), .server = argv[1], .local_id = argv[2],
        .remote_id = argv[3], .psk = (uint8_t*)secret, .psk_length = length,
        .timeout_ms = 25000, .log = log_line };
    int requested = argc == 5 ? 2 : 1, completed = 0, result = 1, traffic = 2;
    sb_status status = { .size = sizeof(status) };
    for (int cycle = 0; cycle < requested; ++cycle) {
        sb_engine *engine = NULL;
        result = sb_engine_start(&config, &engine);
        traffic = result ? 2 : sb_engine_dns_probe(engine, "8.8.8.8", 8000);
        if (engine) { sb_engine_status(engine, &status); sb_engine_stop(engine); }
        if (result || traffic) { break; }
        ++completed;
    }
    SecureZeroMemory(secret, sizeof(secret));
    printf("{\"EngineResult\":%d,\"Authenticated\":%u,\"ChildSaUp\":%u,\"VirtualIPv4\":\"%s\","
        "\"DnsTrafficPassed\":%s,\"EspTx\":%llu,\"EspRx\":%llu,\"PlainRx\":%llu,\"CyclesRequested\":%d,\"CyclesCompleted\":%d}\n",
        result, status.authenticated, status.child_up, status.virtual_address, traffic ? "false" : "true",
        (unsigned long long)status.esp_tx, (unsigned long long)status.esp_rx, (unsigned long long)status.plain_rx, requested, completed);
    return result || traffic || completed != requested ? 2 : 0;
}
