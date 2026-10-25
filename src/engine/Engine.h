/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <stdint.h>
#include "Policy.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sb_engine sb_engine;
typedef int (*sb_send_cb)(void *, const uint8_t *, uint32_t);
typedef void (*sb_plain_cb)(void *, const uint8_t *, uint32_t);
typedef void (*sb_log_cb)(void *, const char *);

typedef struct {
    uint32_t size;
    const char *server;
    const char *local_id;
    const char *remote_id;
    const uint8_t *psk;
    uint32_t psk_length;
    uint32_t timeout_ms;
    sb_log_cb log;
    void *context;
} sb_config;

typedef struct {
    uint32_t size;
    uint32_t authenticated;
    uint32_t child_up;
    uint32_t ike_id;
    uint32_t spi_in;
    uint32_t spi_out;
    uint32_t local_port;
    char local_address[64];
    char server_address[64];
    char virtual_address[64];
    char dns[4][64];
    uint32_t dns_count;
    uint64_t ike_tx;
    uint64_t ike_rx;
    uint64_t esp_tx;
    uint64_t esp_rx;
    uint64_t plain_tx;
    uint64_t plain_rx;
} sb_status;

typedef struct {
    uint32_t size;
    uint32_t enabled, negotiated, pending;
    uint32_t attempts, completed, updates_sent, updates_acked;
    uint32_t sa_updates, last_error, probes_completed;
    uint32_t ike_id, spi_in, spi_out, local_port;
    uint64_t ike_spi_i, ike_spi_r; /* Host byte order, like the Child SA SPIs. */
    char verified_local[64];
} sb_mobike_status;

typedef struct {
    uint32_t size;
    uint32_t local_port;
    char local_address[64];
} sb_path;

typedef struct {
    uint32_t size;
    uint32_t ike_completed, child_completed, child_id;
    uint32_t ike_establishments, child_establishments;
} sb_rekey_status;

#ifdef SB_ENGINE_EXPORTS
#define SB_API __declspec(dllexport)
#else
#define SB_API __declspec(dllimport)
#endif

SB_API int sb_engine_start(const sb_config *config, sb_engine **engine);
SB_API int sb_engine_start_ex(const sb_config *config, const sb_policy *policy, sb_engine **engine);
/* Mobility is opt-in without changing the existing configuration/policy ABI. */
SB_API int sb_engine_start_mobike(const sb_config *config, const sb_policy *policy, uint32_t enabled, sb_engine **engine);
SB_API int sb_engine_start_lifecycle(const sb_config *config, const sb_policy *policy,
    const sb_rekey_policy *rekey, uint32_t mobike, sb_engine **engine);
SB_API int sb_engine_validate_policy(const sb_policy *policy);
SB_API void sb_engine_status(sb_engine *engine, sb_status *status);
SB_API void sb_engine_mobike_status(sb_engine *engine, sb_mobike_status *status);
SB_API void sb_engine_rekey_status(sb_engine *engine, sb_rekey_status *status);
SB_API void sb_engine_lifecycle_status(sb_engine *engine, sb_status *status,
    sb_mobike_status *mobility, sb_rekey_status *rekey);
SB_API int sb_engine_probe_path(sb_engine *engine, sb_path *path);
SB_API uint32_t sb_engine_underlay_interface(sb_engine *engine);
SB_API int sb_engine_roam(sb_engine *engine, const char *local_address, uint32_t local_port);
SB_API int sb_engine_handoff(sb_engine *engine, sb_send_cb send, sb_plain_cb receive, void *context);
SB_API int sb_engine_attach_ip_receiver(sb_engine *engine, sb_plain_cb receive, void *context);
SB_API int sb_engine_rebind_udp(sb_engine *engine, const char *local_address, sb_path *path);
SB_API void sb_engine_feed_udp(sb_engine *engine, const uint8_t *packet, uint32_t length);
SB_API int sb_engine_send_ip(sb_engine *engine, const uint8_t *packet, uint32_t length);
SB_API int sb_engine_dns_probe(sb_engine *engine, const char *resolver, uint32_t timeout_ms);
SB_API void sb_engine_stop(sb_engine *engine);

#ifdef __cplusplus
}
#endif
