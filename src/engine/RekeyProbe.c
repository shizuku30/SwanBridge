/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "Engine.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static void log_line(void *context, const char *line)
{
    fprintf(stderr, "[%llu] %s\n", (unsigned long long)GetTickCount64(), line);
}

static int number(const char *text, uint32_t *value)
{
    char *end;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno || !text[0] || text[0] == '-' || *end) { return 0; }
    *value = parsed;
    return 1;
}

static void snapshot(sb_engine *engine, ULONGLONG started, int traffic, uint32_t failures, int final)
{
    sb_status state = { .size = sizeof(state) };
    sb_mobike_status mobility = { .size = sizeof(mobility) };
    sb_rekey_status rekey = { .size = sizeof(rekey) };
    sb_engine_lifecycle_status(engine, &state, &mobility, &rekey);
    printf("{\"Final\":%s,\"ElapsedMs\":%llu,\"Authenticated\":%s,\"ChildSaUp\":%s,"
        "\"VirtualIPv4\":\"%s\",\"LocalIPv4\":\"%s\",\"IkeUniqueId\":%u,\"ChildUniqueId\":%u,"
        "\"IkeSpiInitiator\":%llu,\"IkeSpiResponder\":%llu,\"ChildSpiIn\":%u,\"ChildSpiOut\":%u,"
        "\"IkeRekeysCompleted\":%u,\"ChildRekeysCompleted\":%u,\"IkeEstablishments\":%u,\"ChildEstablishments\":%u,"
        "\"DnsTrafficPassed\":%s,\"TrafficFailures\":%u,\"EspTx\":%llu,\"EspRx\":%llu}\n",
        final ? "true" : "false", (unsigned long long)(GetTickCount64() - started),
        state.authenticated ? "true" : "false", state.child_up ? "true" : "false",
        state.virtual_address, state.local_address, state.ike_id, rekey.child_id,
        (unsigned long long)mobility.ike_spi_i, (unsigned long long)mobility.ike_spi_r,
        state.spi_in, state.spi_out, rekey.ike_completed, rekey.child_completed,
        rekey.ike_establishments, rekey.child_establishments, traffic ? "false" : "true", failures,
        (unsigned long long)state.esp_tx, (unsigned long long)state.esp_rx);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    uint32_t seconds;
    sb_policy policy = sb_policy_defaults();
    sb_rekey_policy rekey = sb_rekey_policy_defaults();
    policy.child_lifetime = 300;
    if (argc != 8 || !number(argv[4], &seconds) || seconds < 30 || seconds > 600 ||
        !number(argv[5], &rekey.ike_time) || !number(argv[6], &rekey.child_percent) ||
        !number(argv[7], &rekey.jitter_percent) || !sb_rekey_policy_valid(&rekey)) {
        fprintf(stderr, "Usage: SwanBridge.RekeyProbe.exe server local-id remote-id seconds ike-rekey child-percent jitter-percent (PSK on stdin)\n");
        return 1;
    }
    char secret[1025];
    if (!fgets(secret, sizeof(secret), stdin)) { return 1; }
    size_t length = strcspn(secret, "\r\n");
    sb_config config = { .size = sizeof(config), .server = argv[1], .local_id = argv[2],
        .remote_id = argv[3], .psk = (uint8_t*)secret, .psk_length = length,
        .timeout_ms = 25000, .log = log_line };
    sb_engine *engine = NULL;
    int result = sb_engine_start_lifecycle(&config, &policy, &rekey, 1, &engine);
    SecureZeroMemory(secret, sizeof(secret));
    if (result) { if (engine) sb_engine_stop(engine); return 2; }
    ULONGLONG started = GetTickCount64();
    uint32_t failures = 0;
    do {
        int traffic = sb_engine_dns_probe(engine, "8.8.8.8", 2000);
        failures += traffic != 0;
        snapshot(engine, started, traffic, failures, 0);
        Sleep(1000);
    } while (GetTickCount64() - started < (ULONGLONG)seconds * 1000);
    int traffic = sb_engine_dns_probe(engine, "8.8.8.8", 3000);
    failures += traffic != 0;
    snapshot(engine, started, traffic, failures, 1);
    sb_engine_stop(engine);
    return failures ? 2 : 0;
}
