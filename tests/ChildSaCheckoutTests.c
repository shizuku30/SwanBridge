/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <windows.h>
#include <library.h>
#include <daemon.h>
#include <sa/child_sa_manager.h>
#include <stdio.h>

static child_sa_manager_t *manager;
static child_sa_t child;
static ike_sa_t old_sa, new_sa;
static ike_sa_id_t *old_id, *new_id;
static host_t *local, *remote;
static unsigned int mode, checkouts;

static void check(bool valid, const char *text)
{
    printf("%s %s\n", valid ? "PASS" : "FAIL", text);
    if (!valid) { exit(1); }
}
static uint32_t child_id(child_sa_t *this) { return 42; }
static protocol_id_t child_protocol(child_sa_t *this) { return PROTO_ESP; }
static uint32_t child_spi(child_sa_t *this, bool inbound) { return htonl(inbound ? 1234 : 5678); }
static ike_sa_id_t *sa_id(ike_sa_t *this) { return this == &old_sa ? old_id : new_id; }
static host_t *my_host(ike_sa_t *this) { return local; }
static host_t *other_host(ike_sa_t *this) { return remote; }
static enumerator_t *children(ike_sa_t *this)
{
    return this == &new_sa ? enumerator_create_single(&child, NULL) : enumerator_create_empty();
}
static ike_sa_t *checkout(ike_sa_manager_t *this, ike_sa_id_t *id)
{
    ++checkouts;
    if (id->equals(id, old_id)) {
        if (mode != 2) {
            manager->remove(manager, &child);
            if (mode == 0) { manager->add(manager, &child, &new_sa); }
        }
        return &old_sa;
    }
    return id->equals(id, new_id) ? &new_sa : NULL;
}
static void checkin(ike_sa_manager_t *this, ike_sa_t *sa) {}

int main(void)
{
    char configuration[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, configuration, sizeof(configuration));
    char *separator = length && length < sizeof(configuration) ? strrchr(configuration, '\\') : NULL;
    check(separator && (size_t)(separator - configuration) + sizeof("\\probe.conf") <= sizeof(configuration),
        "find package-relative checkout test configuration");
    strcpy(separator + 1, "probe.conf");
    if (!library_init(configuration, "swanbridge-checkout-tests")) { return 1; }
    daemon_t daemon = {0};
    ike_sa_manager_t ike_manager = { .checkout = checkout, .checkin = checkin };
    charon = &daemon;
    daemon.ike_sa_manager = &ike_manager;
    manager = child_sa_manager_create();
    daemon.child_sa_manager = manager;
    child.get_unique_id = child_id; child.get_protocol = child_protocol; child.get_spi = child_spi;
    old_sa.get_id = new_sa.get_id = sa_id;
    old_sa.get_my_host = new_sa.get_my_host = my_host;
    old_sa.get_other_host = new_sa.get_other_host = other_host;
    old_sa.create_child_sa_enumerator = new_sa.create_child_sa_enumerator = children;
    old_id = ike_sa_id_create(IKEV2, 1, 2, TRUE);
    new_id = ike_sa_id_create(IKEV2, 3, 4, TRUE);
    local = host_create_from_string("192.0.2.10", 4500);
    remote = host_create_from_string("198.51.100.1", 4500);
    manager->add(manager, &child, &old_sa);
    child_sa_t *selected = NULL;
    check(manager->checkout(manager, PROTO_ESP, htonl(1234), local, &selected) == &new_sa &&
        selected == &child && checkouts == 2, "SPI lookup follows a Child SA inherited during IKE rekey");
    manager->remove(manager, &child); manager->add(manager, &child, &old_sa); checkouts = 0;
    check(manager->checkout_by_id(manager, 42, NULL) == &new_sa && checkouts == 2,
        "unique-ID lookup recovers the same IKE rekey race");
    manager->remove(manager, &child); manager->add(manager, &child, &old_sa); checkouts = 0; mode = 1;
    check(!manager->checkout_by_id(manager, 42, NULL) && checkouts == 1,
        "a genuinely deleted Child SA is not revived or replaced by another child");
    manager->add(manager, &child, &old_sa); checkouts = 0; mode = 2;
    check(!manager->checkout_by_id(manager, 42, NULL) && checkouts == 2,
        "a permanently stale index is bounded instead of retrying forever");
    manager->remove(manager, &child); manager->destroy(manager);
    old_id->destroy(old_id); new_id->destroy(new_id);
    local->destroy(local); remote->destroy(remote);
    charon = NULL;
    library_deinit();
    return 0;
}
