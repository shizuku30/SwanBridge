/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <library.h>
#include <ipsec_sa_mgr.h>
#include <stdio.h>

static void check(bool valid, const char *name)
{
    printf("%s %s\n", valid ? "PASS" : "FAIL", name);
    if (!valid) { exit(1); }
}

static void migrate_sa(ipsec_sa_mgr_t *manager, bool inbound)
{
    host_t *old_src = host_create_from_string(inbound ? "198.51.100.1" : "192.0.2.10", 4500);
    host_t *old_dst = host_create_from_string(inbound ? "192.0.2.10" : "198.51.100.1", 4500);
    host_t *new_src = host_create_from_string(inbound ? "198.51.100.1" : "192.0.2.20", 4600);
    host_t *new_dst = host_create_from_string(inbound ? "192.0.2.20" : "198.51.100.1", 4700);
    lifetime_cfg_t lifetime = {0};
    mark_t mark = {0};
    /* Synthetic crypto fixture only. No user credential or network is used. */
    uint8_t key[32] = {0};
    chunk_t bytes = chunk_create(key, sizeof(key));
    uint32_t spi = htonl(inbound ? 0x12345678 : 0x87654321), seqno;
    check(manager->add_sa(manager, old_src, old_dst, spi, IPPROTO_ESP, 7, mark,
        0, &lifetime, ENCR_AES_CBC, bytes, AUTH_HMAC_SHA2_256_128, bytes,
        MODE_TUNNEL, IPCOMP_NONE, 0, TRUE, TRUE, FALSE, inbound, FALSE) == SUCCESS,
        "install synthetic ESP SA without starting a tunnel");
    ipsec_sa_t *before = manager->checkout_by_spi(manager, spi, old_dst);
    check(before != NULL, "find original SA");
    esp_context_t *context = before->get_esp_context(before);
    aead_t *crypto = context->get_aead(context);
    if (inbound) {
        check(context->verify_seqno(context, 42), "new inbound ESP sequence accepted");
        context->set_authenticated_seqno(context, 42);
    } else {
        check(context->next_seqno(context, &seqno) && seqno == 1, "outbound sequence begins at one");
    }
    before->update_usestats(before, 123);
    manager->checkin(manager, before);
    check(manager->update_sa(manager, spi, IPPROTO_ESP, 0, old_src, old_dst,
        new_src, new_dst, TRUE, TRUE, mark) == SUCCESS, "migrate installed ESP endpoints in place");
    ipsec_sa_t *after = manager->checkout_by_spi(manager, spi, new_dst);
    check(after == before && after->get_spi(after) == spi && after->get_reqid(after) == 7,
        "migration preserves the SA object, SPI and reqid");
    check(after->get_source(after)->equals(after->get_source(after), new_src) &&
        after->get_destination(after)->equals(after->get_destination(after), new_dst) && after->get_encap(after),
        "migration updates both IP addresses and UDP ports");
    check(after->get_esp_context(after) == context && context->get_aead(context) == crypto,
        "migration retains the original crypto context and keys");
    if (inbound) {
        check(context->get_seqno(context) == 42 && !context->verify_seqno(context, 42) &&
            context->verify_seqno(context, 43), "inbound replay window is not reset by migration");
    } else {
        check(context->next_seqno(context, &seqno) && seqno == 2,
            "outbound ESP sequence continues rather than restarting");
    }
    uint64_t count = 0, packets = 0;
    after->get_usestats(after, &count, &packets, NULL);
    check(count == 123 && packets == 1, "migration retains SA usage counters");
    manager->checkin(manager, after);
    check(manager->update_sa(manager, htonl(9), IPPROTO_ESP, 0, new_src, new_dst,
        old_src, old_dst, TRUE, TRUE, mark) != SUCCESS, "missing SA cannot report a successful update");
    old_src->destroy(old_src); old_dst->destroy(old_dst);
    new_src->destroy(new_src); new_dst->destroy(new_dst);
}

int main(void)
{
    char configuration[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, configuration, sizeof(configuration));
    char *separator = length && length < sizeof(configuration) ? strrchr(configuration, '\\') : NULL;
    check(separator && (size_t)(separator - configuration) + sizeof("\\probe.conf") <= sizeof(configuration),
        "find package-relative offline configuration");
    strcpy(separator + 1, "probe.conf");
    check(library_init(configuration, "swanbridge-mobility-tests"), "initialize isolated library");
    check(lib->plugins->load(lib->plugins, "openssl nonce"), "load bundled crypto implementations");
    ipsec_sa_mgr_t *manager = ipsec_sa_mgr_create();
    migrate_sa(manager, FALSE);
    migrate_sa(manager, TRUE);
    manager->destroy(manager);
    library_deinit();
    return 0;
}
