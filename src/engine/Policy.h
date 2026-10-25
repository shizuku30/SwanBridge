/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <stdint.h>
#include <string.h>

#define SB_ID_FQDN 1
#define SB_ID_IPV4 2
#define SB_IKE_PROPOSAL_COUNT 4
#define SB_ESP_PROPOSAL_COUNT 3

static const char *const sb_ike_proposals[SB_IKE_PROPOSAL_COUNT] = {
    "aes256-sha256-modp2048", "aes128-sha256-modp2048",
    "aes192-sha256-modp2048", "aes256-sha256-modp3072"
};
static const char *const sb_esp_proposals[SB_ESP_PROPOSAL_COUNT] = {
    "aes256-sha256", "aes128-sha256", "aes192-sha256"
};

typedef struct {
    uint32_t size;
    uint32_t version;
    const char *ike_proposal;
    const char *esp_proposal;
    uint32_t local_id_type;
    uint32_t remote_id_type;
    uint32_t dpd_delay;
    uint32_t keep_alive;
    uint32_t retransmit_timeout;
    uint32_t retransmit_tries;
    uint32_t keyingtries;
    uint32_t child_lifetime;
    uint32_t fragmentation;
    uint32_t nat_port;
} sb_policy;

/* Separate from sb_policy so existing callers retain the 64-byte policy ABI. */
typedef struct {
    uint32_t size;
    uint32_t version;
    uint32_t ike_time;
    uint32_t child_percent;
    uint32_t jitter_percent;
} sb_rekey_policy;

static inline sb_rekey_policy sb_rekey_policy_defaults(void)
{
    sb_rekey_policy value = { sizeof(sb_rekey_policy), 1, 14400, 90, 5 };
    return value;
}

static inline int sb_rekey_policy_valid(const sb_rekey_policy *policy)
{
    return policy && policy->size == sizeof(*policy) && policy->version == 1 &&
        (!policy->ike_time || (policy->ike_time >= 60 && policy->ike_time <= 604800)) &&
        (!policy->child_percent || (policy->child_percent >= 10 && policy->child_percent <= 95)) &&
        policy->jitter_percent <= 25;
}

static inline sb_policy sb_policy_defaults(void)
{
    sb_policy value = { sizeof(sb_policy), 1, "aes256-sha256-modp2048", "aes256-sha256",
        SB_ID_FQDN, SB_ID_IPV4, 20, 15, 1, 3, 1, 86400, 1, 4500 };
    return value;
}

static inline int sb_policy_valid(const sb_policy *policy)
{
    unsigned int i;
    int ike = 0, esp = 0;
    if (!policy || policy->size != sizeof(*policy) || policy->version != 1 ||
        !policy->ike_proposal || !policy->esp_proposal) { return 0; }
    for (i = 0; i < SB_IKE_PROPOSAL_COUNT; ++i) { ike |= !strcmp(policy->ike_proposal, sb_ike_proposals[i]); }
    for (i = 0; i < SB_ESP_PROPOSAL_COUNT; ++i) { esp |= !strcmp(policy->esp_proposal, sb_esp_proposals[i]); }
    return ike && esp && (policy->local_id_type == SB_ID_FQDN || policy->local_id_type == SB_ID_IPV4) &&
        (policy->remote_id_type == SB_ID_FQDN || policy->remote_id_type == SB_ID_IPV4) &&
        policy->dpd_delay <= 300 && policy->keep_alive >= 5 && policy->keep_alive <= 120 &&
        policy->retransmit_timeout >= 1 && policy->retransmit_timeout <= 10 &&
        policy->retransmit_tries >= 1 && policy->retransmit_tries <= 8 &&
        policy->keyingtries >= 1 && policy->keyingtries <= 6 &&
        policy->child_lifetime >= 300 && policy->child_lifetime <= 172800 &&
        policy->fragmentation <= 1 && policy->nat_port >= 1 && policy->nat_port <= 65535;
}
