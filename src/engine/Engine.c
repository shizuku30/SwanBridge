/* SPDX-License-Identifier: GPL-2.0-or-later
 * The IPsec backend forwards to strongSwan libipsec, following its
 * kernel-libipsec adapter by Tobias Brunner (2012-2013).
 */
#define SB_ENGINE_EXPORTS
#include "Engine.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <library.h>
#include <daemon.h>
#include <ipsec.h>
#include <kernel/kernel_ipsec.h>
#include <kernel/kernel_net.h>
#include <network/socket.h>
#include <collections/blocking_queue.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/keys/shared_key.h>
#include <bus/listeners/listener.h>
#include <bus/listeners/logger.h>
#include <attributes/attribute_handler.h>
#include <threading/thread.h>
#include <sa/ike_sa.h>
#include <sa/task_manager.h>
#include <sa/ikev2/tasks/ike_mobike.h>
#include <encoding/message.h>
#include <encoding/payloads/notify_payload.h>
#include <processing/jobs/callback_job.h>
#include <stdio.h>

struct sb_engine {
    SOCKET transport;
    HANDLE receiver;
    HANDLE dns_event;
    volatile LONG stop_receiver;
    volatile LONG stopping;
    volatile LONG external;
    volatile LONG queued_ike;
    blocking_queue_t *incoming;
    host_t *local;
    host_t *remote;
    host_t *vip;
    mem_cred_t *credentials;
    listener_t listener;
    logger_t logger;
    attribute_handler_t attributes;
    ipsec_event_listener_t ipsec_listener;
    CRITICAL_SECTION lock;
    sb_status status;
    sb_mobike_status mobility;
    sb_rekey_status rekey;
    uint32_t migration_ike_id, migration_spi_in, migration_spi_out, update_message_id;
    bool update_message_valid, completion_queued, force_roam, last_request_update, migration_update_acked, migration_rekeyed;
    ULONGLONG migration_started;
    char migration_virtual[64];
    sb_send_cb send;
    sb_plain_cb receive;
    sb_log_cb log;
    void *log_context;
    void *packet_context;
    uint16_t dns_id;
    uint16_t dns_port;
};

static sb_engine *active;
static volatile LONG reserved;
_Static_assert(sizeof(sb_config) == 64, "x64 configuration ABI");
_Static_assert(sizeof(sb_policy) == 64, "x64 policy ABI");
_Static_assert(offsetof(sb_status, ike_tx) == 480, "x64 status counter alignment");
_Static_assert(sizeof(sb_status) == 528, "x64 status ABI");
_Static_assert(sizeof(sb_mobike_status) == 144, "x64 mobility status ABI");
_Static_assert(sizeof(sb_path) == 72, "x64 path ABI");
_Static_assert(sizeof(sb_rekey_policy) == 20, "rekey policy ABI");
_Static_assert(sizeof(sb_rekey_status) == 24, "rekey status ABI");
static void free_host(void *object) { ((host_t*)object)->destroy(object); }

static void log_message(char const *message)
{
    if (active && active->log) { active->log(active->log_context, message); }
}

static void debug_log(debug_t group, level_t level, char *format, ...)
{
    if (level <= LEVEL_CTRL) {
        char text[2048];
        va_list args;
        va_start(args, format);
        vsnprintf(text, sizeof(text), format, args);
        va_end(args);
        log_message(text);
    }
}

static int send_udp(sb_engine *engine, chunk_t data)
{
    if (engine->external) {
        return engine->send && engine->send(engine->packet_context, data.ptr, data.len);
    }
    EnterCriticalSection(&engine->lock);
    int sent = engine->transport != INVALID_SOCKET &&
        send(engine->transport, (char*)data.ptr, data.len, 0) == (int)data.len;
    LeaveCriticalSection(&engine->lock);
    return sent;
}

static NET_IFINDEX physical_default_interface(sb_engine *engine, const struct sockaddr *destination, const char *required_address)
{
    MIB_IPFORWARD_TABLE2 *table = NULL;
    SOCKADDR_INET remote = {0};
    NET_IFINDEX best = 0;
    uint64_t best_metric = UINT64_MAX;
    memcpy(&remote.Ipv4, destination, sizeof(remote.Ipv4));
    if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR) { return 0; }
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        MIB_IPFORWARD_ROW2 *row = &table->Table[i];
        if (row->DestinationPrefix.PrefixLength || row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr || row->Loopback) { continue; }
        MIB_IPINTERFACE_ROW iface;
        InitializeIpInterfaceEntry(&iface);
        iface.Family = AF_INET;
        iface.InterfaceLuid = row->InterfaceLuid;
        if (GetIpInterfaceEntry(&iface) != NO_ERROR || !iface.Connected) { continue; }
        MIB_IPFORWARD_ROW2 selected;
        SOCKADDR_INET source = {0};
        if (GetBestRoute2(&row->InterfaceLuid, 0, NULL, &remote, 0, &selected, &source) != NO_ERROR ||
            source.si_family != AF_INET) { continue; }
        uint32_t address = ntohl(source.Ipv4.sin_addr.s_addr);
        char text[64];
        if (!address || (address >> 24) == 127 || (address >> 16) == 0xa9fe || (address >> 28) >= 14 ||
            !inet_ntop(AF_INET, &source.Ipv4.sin_addr, text, sizeof(text))) { continue; }
        if (engine->vip && memeq(&source.Ipv4.sin_addr, engine->vip->get_address(engine->vip).ptr, 4)) { continue; }
        if (required_address && strcmp(required_address, text)) { continue; }
        uint64_t metric = (uint64_t)row->Metric + iface.Metric;
        if (metric < best_metric) { best_metric = metric; best = row->InterfaceIndex; }
    }
    FreeMibTable(table);
    return best;
}

static bool pin_udp_interface(SOCKET socket, NET_IFINDEX index)
{
    DWORD value = htonl(index);
    return index && !setsockopt(socket, IPPROTO_IP, IP_UNICAST_IF, (char*)&value, sizeof(value));
}

typedef struct { socket_t public; } bridge_socket;

METHOD(socket_t, socket_receive, status_t, bridge_socket *this, packet_t **packet)
{
    *packet = active->incoming->dequeue(active->incoming);
    InterlockedDecrement(&active->queued_ike);
    return SUCCESS;
}

METHOD(socket_t, socket_send, status_t, bridge_socket *this, packet_t *packet)
{
    chunk_t data = packet->get_data(packet);
    if (data.len == 1 && data.ptr[0] == 0xff) { return send_udp(active, data) ? SUCCESS : FAILED; }
    int sent = send_udp(active, data);
    if (sent) { InterlockedIncrement64((LONG64*)&active->status.ike_tx); }
    return sent ? SUCCESS : FAILED;
}

METHOD(socket_t, socket_port, uint16_t, bridge_socket *this, bool nat_t)
{
    EnterCriticalSection(&active->lock);
    uint16_t port = active->local->get_port(active->local);
    LeaveCriticalSection(&active->lock);
    return port;
}

METHOD(socket_t, socket_families, socket_family_t, bridge_socket *this)
{
    return SOCKET_FAMILY_IPV4;
}

METHOD(socket_t, socket_destroy, void, bridge_socket *this) { free(this); }

static socket_t *create_socket(void)
{
    bridge_socket *socket;
    INIT(socket, .public = { .receive = _socket_receive, .send = _socket_send,
        .get_port = _socket_port, .supported_families = _socket_families, .destroy = _socket_destroy });
    return &socket->public;
}

typedef struct { kernel_net_t public; } bridge_net;
METHOD(kernel_net_t, net_features, kernel_feature_t, bridge_net *this) { return 0; }
METHOD(kernel_net_t, net_source, host_t*, bridge_net *this, host_t *dest, host_t *src)
{
    host_t *local = NULL;
    EnterCriticalSection(&active->lock);
    if (dest->ip_equals(dest, active->remote) &&
        (!src || (!active->force_roam && src->ip_equals(src, active->local))))
        local = active->local->clone(active->local);
    LeaveCriticalSection(&active->lock);
    return local;
}
METHOD(kernel_net_t, net_nexthop, host_t*, bridge_net *this, host_t *dest, int prefix, host_t *src, char **iface)
{
    if (iface) { *iface = strdup("swanbridge"); }
    EnterCriticalSection(&active->lock);
    host_t *remote = active->remote->clone(active->remote);
    LeaveCriticalSection(&active->lock);
    return remote;
}
METHOD(kernel_net_t, net_interface, bool, bridge_net *this, host_t *host, char **name)
{
    if (name) { *name = strdup("swanbridge"); }
    return TRUE;
}
METHOD(kernel_net_t, net_addresses, enumerator_t*, bridge_net *this, kernel_address_type_t which)
{
    host_t *address = NULL;
    EnterCriticalSection(&active->lock);
    if ((which & ADDR_TYPE_VIRTUAL) && active->vip) {
        address = active->vip->clone(active->vip);
    } else if (which & ADDR_TYPE_REGULAR) {
        address = active->local->clone(active->local);
    }
    LeaveCriticalSection(&active->lock);
    return address ? enumerator_create_single(address, free_host) : enumerator_create_empty();
}
METHOD(kernel_net_t, net_subnets, enumerator_t*, bridge_net *this) { return enumerator_create_empty(); }
METHOD(kernel_net_t, net_add_ip, status_t, bridge_net *this, host_t *ip, int prefix, char *iface)
{
    EnterCriticalSection(&active->lock);
    DESTROY_IF(active->vip);
    active->vip = ip->clone(ip);
    LeaveCriticalSection(&active->lock);
    return SUCCESS;
}
METHOD(kernel_net_t, net_del_ip, status_t, bridge_net *this, host_t *ip, int prefix, bool wait) { return SUCCESS; }
METHOD(kernel_net_t, net_add_route, status_t, bridge_net *this, chunk_t dst, uint8_t prefix,
    host_t *gateway, host_t *src, char *iface, bool pass) { return NOT_SUPPORTED; }
METHOD(kernel_net_t, net_del_route, status_t, bridge_net *this, chunk_t dst, uint8_t prefix,
    host_t *gateway, host_t *src, char *iface, bool pass) { return NOT_SUPPORTED; }
METHOD(kernel_net_t, net_destroy, void, bridge_net *this) { free(this); }
static kernel_net_t *create_net(void)
{
    bridge_net *net;
    INIT(net, .public = { .get_features = _net_features, .get_source_addr = _net_source,
        .get_nexthop = _net_nexthop, .get_interface = _net_interface, .create_address_enumerator = _net_addresses,
        .create_local_subnet_enumerator = _net_subnets, .add_ip = _net_add_ip, .del_ip = _net_del_ip,
        .add_route = _net_add_route, .del_route = _net_del_route, .destroy = _net_destroy });
    return &net->public;
}

typedef struct { kernel_ipsec_t public; } bridge_ipsec;
METHOD(kernel_ipsec_t, ipsec_features, kernel_feature_t, bridge_ipsec *this)
{ return KERNEL_ESP_V3_TFC | KERNEL_SA_USE_TIME | KERNEL_REQUIRE_UDP_ENCAPSULATION; }
METHOD(kernel_ipsec_t, ipsec_spi, status_t, bridge_ipsec *this, host_t *src, host_t *dst, uint8_t protocol, uint32_t *spi)
{ return ipsec->sas->get_spi(ipsec->sas, src, dst, protocol, spi); }
METHOD(kernel_ipsec_t, ipsec_cpi, status_t, bridge_ipsec *this, host_t *src, host_t *dst, uint16_t *cpi) { return NOT_SUPPORTED; }
METHOD(kernel_ipsec_t, ipsec_add, status_t, bridge_ipsec *this, kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
    if (!data->encap) { return NOT_SUPPORTED; }
    return ipsec->sas->add_sa(ipsec->sas, id->src, id->dst, id->spi, id->proto,
        data->reqid, id->mark, data->tfc, data->lifetime, data->enc_alg, data->enc_key,
        data->int_alg, data->int_key, data->mode, data->ipcomp, data->cpi, data->initiator,
        data->encap, data->esn, data->inbound, data->update);
}
METHOD(kernel_ipsec_t, ipsec_update, status_t, bridge_ipsec *this, kernel_ipsec_sa_id_t *id, kernel_ipsec_update_sa_t *data)
{
    status_t result = FAILED;
    if (data->new_encap && !data->cpi && data->old_reqid == data->new_reqid)
        result = ipsec->sas->update_sa(ipsec->sas, id->spi, id->proto, data->cpi,
            id->src, id->dst, data->new_src, data->new_dst, data->encap, data->new_encap, id->mark);
    EnterCriticalSection(&active->lock);
    if (result == SUCCESS) { ++active->mobility.sa_updates; }
    else { active->mobility.last_error = 5; }
    LeaveCriticalSection(&active->lock);
    return result;
}
METHOD(kernel_ipsec_t, ipsec_query, status_t, bridge_ipsec *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets, time_t *time)
{ return ipsec->sas->query_sa(ipsec->sas, id->src, id->dst, id->spi, id->proto, id->mark, bytes, packets, time); }
METHOD(kernel_ipsec_t, ipsec_del, status_t, bridge_ipsec *this, kernel_ipsec_sa_id_t *id, kernel_ipsec_del_sa_t *data)
{ return ipsec->sas->del_sa(ipsec->sas, id->src, id->dst, id->spi, id->proto, data->cpi, id->mark); }
METHOD(kernel_ipsec_t, ipsec_flush, status_t, bridge_ipsec *this) { return ipsec->sas->flush_sas(ipsec->sas); }
METHOD(kernel_ipsec_t, policy_add, status_t, bridge_ipsec *this, kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{ return ipsec->policies->add_policy(ipsec->policies, data->src, data->dst, id->src_ts, id->dst_ts, id->dir, data->type, data->sa, id->mark, data->prio); }
METHOD(kernel_ipsec_t, policy_del, status_t, bridge_ipsec *this, kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{ return ipsec->policies->del_policy(ipsec->policies, data->src, data->dst, id->src_ts, id->dst_ts, id->dir, data->type, data->sa, id->mark, data->prio); }
METHOD(kernel_ipsec_t, policy_query, status_t, bridge_ipsec *this, kernel_ipsec_policy_id_t *id, kernel_ipsec_query_policy_t *data, time_t *time) { return NOT_SUPPORTED; }
METHOD(kernel_ipsec_t, policy_flush, status_t, bridge_ipsec *this) { return ipsec->policies->flush_policies(ipsec->policies); }
METHOD(kernel_ipsec_t, ipsec_bypass, bool, bridge_ipsec *this, int fd, int family) { return TRUE; }
METHOD(kernel_ipsec_t, ipsec_decap, bool, bridge_ipsec *this, int fd, int family, uint16_t port) { return FALSE; }
METHOD(kernel_ipsec_t, ipsec_destroy, void, bridge_ipsec *this) { free(this); }
static kernel_ipsec_t *create_ipsec(void)
{
    bridge_ipsec *backend;
    INIT(backend, .public = { .get_features = _ipsec_features, .get_spi = _ipsec_spi,
        .get_cpi = _ipsec_cpi, .add_sa = _ipsec_add, .update_sa = _ipsec_update,
        .query_sa = _ipsec_query, .del_sa = _ipsec_del, .flush_sas = _ipsec_flush,
        .add_policy = _policy_add, .del_policy = _policy_del, .query_policy = _policy_query,
        .flush_policies = _policy_flush, .bypass_socket = _ipsec_bypass,
        .enable_udp_decap = _ipsec_decap, .destroy = _ipsec_destroy });
    return &backend->public;
}

static void expire_sa(uint8_t protocol, uint32_t spi, host_t *dst, bool hard)
{ charon->kernel->expire(charon->kernel, protocol, spi, dst, hard); }

static void outbound(void *context, esp_packet_t *packet, bool encap)
{
    sb_engine *engine = context;
    chunk_t bytes = packet->packet.get_data(&packet->packet);
    if (encap && send_udp(engine, bytes)) { InterlockedIncrement64((LONG64*)&engine->status.esp_tx); }
    packet->destroy(packet);
}

static void inbound(void *context, ip_packet_t *packet)
{
    sb_engine *engine = context;
    chunk_t bytes = packet->get_encoding(packet), payload = packet->get_payload(packet);
    InterlockedIncrement64((LONG64*)&engine->status.plain_rx);
    if (packet->get_next_header(packet) == IPPROTO_UDP && payload.len >= 20 &&
        untoh16(payload.ptr + 2) == engine->dns_port && untoh16(payload.ptr + 8) == engine->dns_id &&
        (payload.ptr[10] & 0x80) && !(payload.ptr[11] & 15) && untoh16(payload.ptr + 14) > 0) {
        SetEvent(engine->dns_event);
    }
    EnterCriticalSection(&engine->lock);
    sb_plain_cb receive_cb = engine->receive;
    void *packet_context = engine->packet_context;
    LeaveCriticalSection(&engine->lock);
    if (receive_cb) { receive_cb(packet_context, bytes.ptr, bytes.len); }
    packet->destroy(packet);
}

void sb_engine_feed_udp(sb_engine *engine, const uint8_t *bytes, uint32_t length)
{
    if (!engine || engine->stopping || length < 4 || length > 65535) { return; }
    packet_t *packet = packet_create();
    EnterCriticalSection(&engine->lock);
    packet->set_source(packet, engine->remote->clone(engine->remote));
    packet->set_destination(packet, engine->local->clone(engine->local));
    LeaveCriticalSection(&engine->lock);
    if (!bytes[0] && !bytes[1] && !bytes[2] && !bytes[3]) {
        if (length < 32) { packet->destroy(packet); return; }
        if (InterlockedIncrement(&engine->queued_ike) > 256) {
            InterlockedDecrement(&engine->queued_ike);
            packet->destroy(packet);
            return;
        }
        packet->set_data(packet, chunk_clone(chunk_create((uint8_t*)bytes, length)));
        InterlockedIncrement64((LONG64*)&engine->status.ike_rx);
        engine->incoming->enqueue(engine->incoming, packet);
    } else {
        packet->set_data(packet, chunk_clone(chunk_create((uint8_t*)bytes, length)));
        InterlockedIncrement64((LONG64*)&engine->status.esp_rx);
        ipsec->processor->queue_inbound(ipsec->processor, esp_packet_create_from_packet(packet));
    }
}

static DWORD WINAPI receive_udp(void *context)
{
    sb_engine *engine = context;
    uint8_t buffer[65535];
    while (!engine->stop_receiver) {
        int count = recv(engine->transport, (char*)buffer, sizeof(buffer), 0);
        if (count > 0 && !engine->stop_receiver) { sb_engine_feed_udp(engine, buffer, count); }
    }
    return 0;
}

static bool ike_changed(listener_t *listener, ike_sa_t *sa, bool up)
{
    EnterCriticalSection(&active->lock);
    if (!up && active->status.ike_id != sa->get_unique_id(sa)) {
        LeaveCriticalSection(&active->lock);
        return TRUE;
    }
    active->status.authenticated = up;
    active->status.ike_id = sa->get_unique_id(sa);
    active->mobility.negotiated = up && sa->supports_extension(sa, EXT_MOBIKE);
    if (up) {
        ++active->rekey.ike_establishments;
        ike_sa_id_t *id = sa->get_id(sa);
        active->mobility.ike_id = sa->get_unique_id(sa);
        active->mobility.ike_spi_i = be64toh(id->get_initiator_spi(id));
        active->mobility.ike_spi_r = be64toh(id->get_responder_spi(id));
    }
    LeaveCriticalSection(&active->lock);
    return TRUE;
}

static bool ike_rekeyed(listener_t *listener, ike_sa_t *old, ike_sa_t *replacement)
{
    EnterCriticalSection(&active->lock);
    if (active->status.ike_id == old->get_unique_id(old)) {
        ike_sa_id_t *id = replacement->get_id(replacement);
        active->status.ike_id = replacement->get_unique_id(replacement);
        active->mobility.ike_id = active->status.ike_id;
        active->mobility.ike_spi_i = be64toh(id->get_initiator_spi(id));
        active->mobility.ike_spi_r = be64toh(id->get_responder_spi(id));
        active->mobility.negotiated = replacement->supports_extension(replacement, EXT_MOBIKE);
        ++active->rekey.ike_completed;
        if (active->mobility.pending) {
            active->migration_ike_id = active->status.ike_id;
            active->migration_rekeyed = TRUE;
        }
    }
    LeaveCriticalSection(&active->lock);
    log_message("SwanBridge: IKE rekey completed; current SA handle advanced without reauthentication");
    return TRUE;
}

static bool child_changed(listener_t *listener, ike_sa_t *sa, child_sa_t *child, bool up)
{
    host_t *address;
    enumerator_t *ips = sa->create_virtual_ip_enumerator(sa, TRUE);
    EnterCriticalSection(&active->lock);
    if (!up && (active->status.spi_in != ntohl(child->get_spi(child, TRUE)) ||
        active->status.spi_out != ntohl(child->get_spi(child, FALSE)))) {
        LeaveCriticalSection(&active->lock);
        ips->destroy(ips);
        return TRUE;
    }
    active->status.child_up = up;
    if (up) { ++active->rekey.child_establishments; }
    active->rekey.child_id = child->get_unique_id(child);
    active->status.spi_in = ntohl(child->get_spi(child, TRUE));
    active->status.spi_out = ntohl(child->get_spi(child, FALSE));
    active->mobility.spi_in = active->status.spi_in;
    active->mobility.spi_out = active->status.spi_out;
    if (ips->enumerate(ips, &address)) {
        chunk_t bytes = address->get_address(address);
        inet_ntop(AF_INET, bytes.ptr, active->status.virtual_address, sizeof(active->status.virtual_address));
    }
    LeaveCriticalSection(&active->lock);
    ips->destroy(ips);
    return TRUE;
}

static bool child_rekeyed(listener_t *listener, ike_sa_t *sa, child_sa_t *old, child_sa_t *replacement)
{
    EnterCriticalSection(&active->lock);
    if (active->status.spi_in == ntohl(old->get_spi(old, TRUE)) &&
        active->status.spi_out == ntohl(old->get_spi(old, FALSE))) {
        active->status.spi_in = ntohl(replacement->get_spi(replacement, TRUE));
        active->status.spi_out = ntohl(replacement->get_spi(replacement, FALSE));
        active->mobility.spi_in = active->status.spi_in;
        active->mobility.spi_out = active->status.spi_out;
        active->rekey.child_id = replacement->get_unique_id(replacement);
        active->status.child_up = TRUE;
        ++active->rekey.child_completed;
        if (active->mobility.pending) {
            active->migration_spi_in = active->status.spi_in;
            active->migration_spi_out = active->status.spi_out;
            active->migration_rekeyed = TRUE;
        }
    }
    LeaveCriticalSection(&active->lock);
    log_message("SwanBridge: Child rekey completed; replacement ESP SPIs tracked without restarting the Windows channel");
    return TRUE;
}

/* Called with the endpoint/status lock held. No credential or key is copied. */
static void begin_migration(sb_engine *engine)
{
    engine->mobility.pending = 1;
    ++engine->mobility.attempts;
    engine->mobility.last_error = 0;
    engine->migration_ike_id = engine->status.ike_id;
    engine->migration_spi_in = engine->status.spi_in;
    engine->migration_spi_out = engine->status.spi_out;
    memcpy(engine->migration_virtual, engine->status.virtual_address, 64);
    engine->migration_started = GetTickCount64();
    engine->update_message_valid = FALSE;
    engine->migration_update_acked = FALSE;
    engine->migration_rekeyed = FALSE;
}

static job_requeue_t finish_migration(void *context)
{
    sb_engine *engine = context;
    if (engine->stopping || active != engine) { return JOB_REQUEUE_NONE; }
    EnterCriticalSection(&engine->lock);
    uint32_t ike_id = engine->migration_ike_id, spi_in = engine->migration_spi_in, spi_out = engine->migration_spi_out;
    LeaveCriticalSection(&engine->lock);
    ike_sa_t *sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager, ike_id);
    bool busy = FALSE, same_child = FALSE, valid = FALSE;
    if (sa) {
        task_t *task;
        child_sa_t *child;
        task_queue_t queues[] = { TASK_QUEUE_ACTIVE, TASK_QUEUE_QUEUED };
        for (unsigned int index = 0; index < countof(queues); ++index) {
            enumerator_t *tasks = sa->create_task_enumerator(sa, queues[index]);
            while (tasks->enumerate(tasks, &task)) { busy |= task->get_type(task) == TASK_IKE_MOBIKE; }
            tasks->destroy(tasks);
        }
        enumerator_t *children = sa->create_child_sa_enumerator(sa);
        while (children->enumerate(children, &child)) {
            same_child |= child->get_state(child) == CHILD_INSTALLED &&
                ntohl(child->get_spi(child, TRUE)) == spi_in &&
                ntohl(child->get_spi(child, FALSE)) == spi_out;
        }
        children->destroy(children);
        EnterCriticalSection(&engine->lock);
        valid = sa->get_state(sa) == IKE_ESTABLISHED && same_child &&
            sa->get_my_host(sa)->equals(sa->get_my_host(sa), engine->local) &&
            !strcmp(engine->migration_virtual, engine->status.virtual_address) && !engine->mobility.last_error;
        LeaveCriticalSection(&engine->lock);
        charon->ike_sa_manager->checkin(charon->ike_sa_manager, sa);
    }
    if (busy && GetTickCount64() - engine->migration_started < 45000) { return JOB_RESCHEDULE_MS(100); }
    EnterCriticalSection(&engine->lock);
    if ((ike_id != engine->migration_ike_id || spi_in != engine->migration_spi_in || spi_out != engine->migration_spi_out) &&
        GetTickCount64() - engine->migration_started < 45000) {
        LeaveCriticalSection(&engine->lock);
        return JOB_RESCHEDULE_MS(100);
    }
    engine->completion_queued = FALSE;
    engine->mobility.pending = 0;
    if (valid && !busy) {
        if (engine->migration_update_acked) { ++engine->mobility.completed; }
        else { ++engine->mobility.probes_completed; }
        memcpy(engine->mobility.verified_local, engine->status.local_address, 64);
        engine->mobility.local_port = engine->status.local_port;
    } else { engine->mobility.last_error = 6; }
    LeaveCriticalSection(&engine->lock);
    log_message(valid && !busy ? (engine->migration_rekeyed ?
        "SwanBridge: MOBIKE path validated across a separately confirmed rekey" :
        "SwanBridge: MOBIKE path validated; IKE and Child SA identities preserved") :
        "SwanBridge: MOBIKE confirmation failed; no successful migration recorded");
    return JOB_REQUEUE_NONE;
}

static bool mobike_message(listener_t *listener, ike_sa_t *sa, message_t *message, bool incoming, bool plain)
{
    if (!plain || message->get_exchange_type(message) != INFORMATIONAL) { return TRUE; }
    bool queue = FALSE;
    EnterCriticalSection(&active->lock);
    if (active->mobility.enabled && active->mobility.negotiated) {
        if (!incoming && message->get_request(message)) {
            bool update = message->get_notify(message, UPDATE_SA_ADDRESSES) != NULL;
            if (update && !active->mobility.pending) { begin_migration(active); }
            if (active->mobility.pending) {
                active->update_message_id = message->get_message_id(message);
                active->update_message_valid = TRUE;
                active->last_request_update = update;
                if (update) { ++active->mobility.updates_sent; }
            }
        } else if (incoming && !message->get_request(message) && active->update_message_valid &&
            message->get_message_id(message) == active->update_message_id) {
            active->update_message_valid = FALSE;
            if (active->last_request_update) {
                ++active->mobility.updates_acked;
                active->migration_update_acked = TRUE;
            }
            if (!active->completion_queued) { active->completion_queued = TRUE; queue = TRUE; }
        }
    }
    LeaveCriticalSection(&active->lock);
    /* Checkout happens in a separate job, after COOKIE2/task processing releases the SA. */
    if (queue) { lib->processor->queue_job(lib->processor, &callback_job_create(finish_migration, active, NULL, NULL)->job); }
    return TRUE;
}

static bool attribute_handle(attribute_handler_t *handler, ike_sa_t *sa, configuration_attribute_type_t type, chunk_t data)
{
    if (type != INTERNAL_IP4_DNS || data.len != 4) { return FALSE; }
    EnterCriticalSection(&active->lock);
    if (active->status.dns_count < 4) {
        inet_ntop(AF_INET, data.ptr, active->status.dns[active->status.dns_count++], 64);
    }
    LeaveCriticalSection(&active->lock);
    return TRUE;
}
static void attribute_release(attribute_handler_t *handler, ike_sa_t *sa, configuration_attribute_type_t type, chunk_t data) {}
typedef struct { enumerator_t public; int done; } dns_enumerator;
METHOD(enumerator_t, dns_enumerate, bool, dns_enumerator *this, va_list args)
{
    configuration_attribute_type_t *type;
    chunk_t *data;
    if (this->done++) { return FALSE; }
    VA_ARGS_VGET(args, type, data);
    *type = INTERNAL_IP4_DNS;
    *data = chunk_empty;
    return TRUE;
}
METHOD(enumerator_t, dns_destroy, void, dns_enumerator *this) { free(this); }
static enumerator_t *attribute_requests(attribute_handler_t *handler, ike_sa_t *sa, linked_list_t *vips)
{
    dns_enumerator *enumerator;
    INIT(enumerator, .public = { .enumerate = enumerator_enumerate_default,
        .venumerate = _dns_enumerate, .destroy = _dns_destroy });
    return &enumerator->public;
}

static bool controller_log(void *context, debug_t group, level_t level, ike_sa_t *sa, const char *message)
{ return TRUE; } /* Keep controller calls synchronous; the permanent logger records events. */

static level_t log_level(logger_t *logger, debug_t group) { return LEVEL_CTRL; }
static void protocol_log(logger_t *logger, debug_t group, level_t level, int thread, ike_sa_t *sa, const char *message)
{ log_message(message); }

static identification_t *configured_identity(const char *value, uint32_t type)
{
    return type == SB_ID_FQDN ? identification_create_from_encoding(ID_FQDN,
        chunk_create((uint8_t*)value, strlen(value))) : identification_create_from_string((char*)value);
}

static peer_cfg_t *create_peer(const sb_config *config, const sb_policy *policy, const sb_rekey_policy *rekey, child_cfg_t **child)
{
    ike_cfg_create_t ike_data = { .version = IKEV2, .local = active->status.local_address,
        .local_port = active->status.local_port, .remote = active->status.server_address,
        .remote_port = policy->nat_port, .no_certreq = TRUE, .force_encap = TRUE,
        .fragmentation = policy->fragmentation ? FRAGMENTATION_YES : FRAGMENTATION_NO };
    ike_cfg_t *ike = ike_cfg_create(&ike_data);
    ike->add_proposal(ike, proposal_create_from_string(PROTO_IKE, policy->ike_proposal));
    peer_cfg_create_t peer_data = { .options = active->mobility.enabled ? 0 : OPT_NO_MOBIKE, .cert_policy = CERT_NEVER_SEND,
        .unique = UNIQUE_NO, .keyingtries = policy->keyingtries, .dpd = policy->dpd_delay,
        .rekey_time = rekey->ike_time, .reauth_time = 0,
        .jitter_time = rekey->ike_time * rekey->jitter_percent / 100,
        .over_time = rekey->ike_time ? max(30, rekey->ike_time / 10) : 0 };
    peer_cfg_t *peer = peer_cfg_create("SwanBridge", ike, &peer_data);
    auth_cfg_t *local_auth = auth_cfg_create(), *remote_auth = auth_cfg_create();
    local_auth->add(local_auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
    local_auth->add(local_auth, AUTH_RULE_IDENTITY,
        configured_identity(config->local_id, policy->local_id_type));
    remote_auth->add(remote_auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
    remote_auth->add(remote_auth, AUTH_RULE_IDENTITY, configured_identity(config->remote_id, policy->remote_id_type));
    peer->add_auth_cfg(peer, local_auth, TRUE);
    peer->add_auth_cfg(peer, remote_auth, FALSE);
    peer->add_virtual_ip(peer, host_create_any(AF_INET));
    uint32_t child_time = policy->child_lifetime * rekey->child_percent / 100;
    child_cfg_create_t child_data = { .mode = MODE_TUNNEL,
        .lifetime = { .time = { .life = policy->child_lifetime, .rekey = child_time,
            .jitter = child_time * rekey->jitter_percent / 100 } } };
    *child = child_cfg_create("SwanBridge", &child_data);
    (*child)->add_proposal(*child, proposal_create_from_string(PROTO_ESP, policy->esp_proposal));
    (*child)->add_traffic_selector(*child, TRUE, traffic_selector_create_dynamic(0, 0, 65535));
    (*child)->add_traffic_selector(*child, FALSE, traffic_selector_create_from_string(0, TS_IPV4_ADDR_RANGE,
        "0.0.0.0", 0, "255.255.255.255", 65535));
    peer->add_child_cfg(peer, (*child)->get_ref(*child));
    return peer;
}

int sb_engine_start(const sb_config *config, sb_engine **output)
{
    const sb_policy policy = sb_policy_defaults();
    return sb_engine_start_ex(config, &policy, output);
}

int sb_engine_validate_policy(const sb_policy *policy)
{
    return sb_policy_valid(policy) ? 0 : 1;
}

int sb_engine_start_ex(const sb_config *config, const sb_policy *policy, sb_engine **output)
{
    return sb_engine_start_mobike(config, policy, 0, output);
}

int sb_engine_start_mobike(const sb_config *config, const sb_policy *policy, uint32_t enabled, sb_engine **output)
{
    sb_rekey_policy rekey = sb_rekey_policy_defaults();
    rekey.ike_time = 0; rekey.child_percent = 0;
    return sb_engine_start_lifecycle(config, policy, &rekey, enabled, output);
}

int sb_engine_start_lifecycle(const sb_config *config, const sb_policy *policy,
    const sb_rekey_policy *rekey, uint32_t enabled, sb_engine **output)
{
    if (!output) { return 1; }
    *output = NULL;
    if (enabled > 1 || !sb_policy_valid(policy) || !sb_rekey_policy_valid(rekey) || !config || config->size != sizeof(*config) || !config->server || !config->local_id ||
        !config->remote_id || !config->psk || !config->psk_length || config->psk_length > 1024 ||
        InterlockedCompareExchange(&reserved, 1, 0)) { return 1; }
    sb_engine *engine = calloc(1, sizeof(*engine));
    if (!engine) { InterlockedExchange(&reserved, 0); return 1; }
    engine->transport = INVALID_SOCKET;
    engine->log = config->log;
    engine->log_context = config->context;
    engine->status.size = sizeof(engine->status);
    engine->mobility.size = sizeof(engine->mobility);
    engine->mobility.enabled = enabled;
    engine->rekey.size = sizeof(engine->rekey);
    InitializeCriticalSection(&engine->lock);
    engine->dns_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    active = engine;
    const char *initialization_stage = "WSAStartup";
    int initialization_error = 0;
    bool winsock_initialized = FALSE;
    WSADATA winsock;
    initialization_error = WSAStartup(MAKEWORD(2, 2), &winsock);
    if (initialization_error) { goto failed_early; }
    winsock_initialized = TRUE;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP }, *addresses = NULL;
    struct sockaddr_in local;
    int local_size = sizeof(local);
    DWORD timeout = 200;
    char service[6];
    snprintf(service, sizeof(service), "%u", policy->nat_port);
    initialization_stage = "DNS resolution";
    initialization_error = getaddrinfo(config->server, service, &hints, &addresses);
    if (initialization_error) { goto failed_early; }
    initialization_stage = "UDP endpoint setup";
    engine->transport = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    NET_IFINDEX initial_interface = enabled ? physical_default_interface(engine, addresses->ai_addr, NULL) : 0;
    if (engine->transport == INVALID_SOCKET || (enabled && !pin_udp_interface(engine->transport, initial_interface)) ||
        connect(engine->transport, addresses->ai_addr, addresses->ai_addrlen) ||
        getsockname(engine->transport, (struct sockaddr*)&local, &local_size)) {
        initialization_error = WSAGetLastError(); freeaddrinfo(addresses); goto failed_early;
    }
    engine->remote = host_create_from_sockaddr(addresses->ai_addr);
    freeaddrinfo(addresses);
    engine->local = host_create_from_sockaddr((struct sockaddr*)&local);
    engine->status.local_port = ntohs(local.sin_port);
    inet_ntop(AF_INET, &local.sin_addr, engine->status.local_address, 64);
    memcpy(engine->mobility.verified_local, engine->status.local_address, 64);
    engine->mobility.local_port = engine->status.local_port;
    inet_ntop(AF_INET, engine->remote->get_address(engine->remote).ptr, engine->status.server_address, 64);
    setsockopt(engine->transport, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    char path[MAX_PATH];
    HMODULE module;
    initialization_stage = "module path lookup";
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (char*)sb_engine_start, &module)) { initialization_error = GetLastError(); goto failed_early; }
    DWORD length = GetModuleFileNameA(module, path, sizeof(path));
    char *slash = length && length < sizeof(path) ? strrchr(path, '\\') : NULL;
    if (!slash || slash - path + sizeof("\\engine.conf") > sizeof(path)) { goto failed_early; }
    strcpy(slash + 1, "engine.conf");
    initialization_stage = "strongSwan library initialization";
    if (!library_init(path, "swanbridge")) { library_deinit(); goto failed_early; }
    lib->settings->set_double(lib->settings, "swanbridge.retransmit_timeout", (double)policy->retransmit_timeout);
    lib->settings->set_int(lib->settings, "swanbridge.retransmit_tries", policy->retransmit_tries);
    lib->settings->set_time(lib->settings, "swanbridge.keep_alive", policy->keep_alive);
    initialization_stage = "charon initialization";
    if (!libcharon_init()) { library_deinit(); goto failed_early; }
    dbg = debug_log;
    initialization_stage = "libipsec initialization";
    if (!libipsec_init()) { libcharon_deinit(); library_deinit(); goto failed_early; }
    engine->incoming = blocking_queue_create();
    plugin_feature_t features[] = {
        PLUGIN_CALLBACK(kernel_ipsec_register, create_ipsec), PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
        PLUGIN_CALLBACK(kernel_net_register, create_net), PLUGIN_PROVIDE(CUSTOM, "kernel-net"),
        PLUGIN_CALLBACK(socket_register, create_socket), PLUGIN_PROVIDE(CUSTOM, "socket")
    };
    lib->plugins->add_static_features(lib->plugins, "swanbridge-adapters", features, countof(features), TRUE, NULL, NULL);
    engine->listener.ike_updown = ike_changed;
    engine->listener.ike_rekey = ike_rekeyed;
    engine->listener.child_updown = child_changed;
    engine->listener.child_rekey = child_rekeyed;
    engine->listener.message = mobike_message;
    engine->attributes.handle = attribute_handle;
    engine->attributes.release = attribute_release;
    engine->attributes.create_attribute_enumerator = attribute_requests;
    engine->ipsec_listener.expire = expire_sa;
    ipsec->events->register_listener(ipsec->events, &engine->ipsec_listener);
    ipsec->processor->register_inbound(ipsec->processor, inbound, engine);
    ipsec->processor->register_outbound(ipsec->processor, outbound, engine);
    engine->credentials = mem_cred_create();
    engine->credentials->add_shared(engine->credentials,
        shared_key_create(SHARED_IKE, chunk_clone(chunk_create((uint8_t*)config->psk, config->psk_length))),
        configured_identity(config->local_id, policy->local_id_type),
        configured_identity(config->remote_id, policy->remote_id_type), NULL);
    lib->credmgr->add_set(lib->credmgr, &engine->credentials->set);
    charon->bus->add_listener(charon->bus, &engine->listener);
    charon->attributes->add_handler(charon->attributes, &engine->attributes);
    if (!charon->initialize(charon, "openssl nonce aes sha2 sha1 hmac")) {
        *output = engine;
        sb_engine_stop(engine);
        *output = NULL;
        return 1;
    }
    engine->logger.get_level = log_level;
    engine->logger.log = protocol_log;
    charon->bus->add_logger(charon->bus, &engine->logger);
    engine->receiver = CreateThread(NULL, 0, receive_udp, engine, 0, NULL);
    if (!engine->receiver) { sb_engine_stop(engine); return 1; }
    charon->start(charon);
    child_cfg_t *child;
    peer_cfg_t *peer = create_peer(config, policy, rekey, &child);
    status_t initiated = charon->controller->initiate(charon->controller, peer, child,
        controller_log, engine, LEVEL_CTRL, config->timeout_ms ? config->timeout_ms : 30000, FALSE);
    *output = engine;
    if (initiated != SUCCESS || !engine->status.authenticated || !engine->status.child_up || !engine->status.virtual_address[0]) {
        log_message("SwanBridge: authenticated Child SA with IPv4 address was not established");
        return 2;
    }
    if (enabled) {
        ike_sa_t *sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager, engine->status.ike_id);
        if (sa) {
            EnterCriticalSection(&engine->lock);
            engine->mobility.negotiated = sa->supports_extension(sa, EXT_MOBIKE);
            LeaveCriticalSection(&engine->lock);
            charon->ike_sa_manager->checkin(charon->ike_sa_manager, sa);
        }
    }
    return 0;

failed_early:
    {
        char error[256];
        snprintf(error, sizeof(error), "SwanBridge: engine initialization failed before IKE negotiation at %s (error %d)",
            initialization_stage, initialization_error);
        log_message(error);
    }
    if (engine->transport != INVALID_SOCKET) { closesocket(engine->transport); }
    DESTROY_IF(engine->local);
    DESTROY_IF(engine->remote);
    CloseHandle(engine->dns_event);
    DeleteCriticalSection(&engine->lock);
    free(engine);
    active = NULL;
    InterlockedExchange(&reserved, 0);
    if (winsock_initialized) { WSACleanup(); }
    return 1;
}

void sb_engine_status(sb_engine *engine, sb_status *status)
{
    if (!engine || !status || status->size != sizeof(*status)) { return; }
    EnterCriticalSection(&engine->lock);
    memcpy(status, &engine->status, sizeof(*status));
    LeaveCriticalSection(&engine->lock);
}

void sb_engine_mobike_status(sb_engine *engine, sb_mobike_status *status)
{
    if (!engine || engine != active || !status || status->size != sizeof(*status)) { return; }
    EnterCriticalSection(&engine->lock);
    memcpy(status, &engine->mobility, sizeof(*status));
    LeaveCriticalSection(&engine->lock);
}

void sb_engine_rekey_status(sb_engine *engine, sb_rekey_status *status)
{
    if (!engine || engine != active || !status || status->size != sizeof(*status)) { return; }
    EnterCriticalSection(&engine->lock);
    memcpy(status, &engine->rekey, sizeof(*status));
    LeaveCriticalSection(&engine->lock);
}

void sb_engine_lifecycle_status(sb_engine *engine, sb_status *status,
    sb_mobike_status *mobility, sb_rekey_status *rekey)
{
    if (!engine || engine != active || !status || status->size != sizeof(*status) ||
        !mobility || mobility->size != sizeof(*mobility) || !rekey || rekey->size != sizeof(*rekey)) { return; }
    EnterCriticalSection(&engine->lock);
    memcpy(status, &engine->status, sizeof(*status));
    memcpy(mobility, &engine->mobility, sizeof(*mobility));
    memcpy(rekey, &engine->rekey, sizeof(*rekey));
    LeaveCriticalSection(&engine->lock);
}

int sb_engine_probe_path(sb_engine *engine, sb_path *path)
{
    if (!engine || engine != active || !path || path->size != sizeof(*path) || engine->stopping) { return 1; }
    host_t *remote;
    EnterCriticalSection(&engine->lock);
    remote = engine->remote->clone(engine->remote);
    path->local_port = engine->status.local_port;
    LeaveCriticalSection(&engine->lock);
    SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in local;
    int size = sizeof(local), result = 2;
    NET_IFINDEX index = physical_default_interface(engine, remote->get_sockaddr(remote), NULL);
    if (probe != INVALID_SOCKET &&
        pin_udp_interface(probe, index) &&
        !connect(probe, remote->get_sockaddr(remote), *remote->get_sockaddr_len(remote)) &&
        !getsockname(probe, (struct sockaddr*)&local, &size)) {
        host_t *candidate = host_create_from_sockaddr((struct sockaddr*)&local);
        EnterCriticalSection(&engine->lock);
        uint32_t address = ntohl(local.sin_addr.s_addr);
        bool usable = candidate && address && (address >> 24) != 127 &&
            (address >> 16) != 0xa9fe && (address >> 28) < 14 &&
            (!engine->vip || !candidate->ip_equals(candidate, engine->vip));
        LeaveCriticalSection(&engine->lock);
        if (usable && inet_ntop(AF_INET, &local.sin_addr, path->local_address, sizeof(path->local_address))) { result = 0; }
        DESTROY_IF(candidate);
    }
    if (probe != INVALID_SOCKET) { closesocket(probe); }
    remote->destroy(remote);
    return result;
}

uint32_t sb_engine_underlay_interface(sb_engine *engine)
{
    if (!engine || engine != active || engine->stopping || engine->external) { return 0; }
    DWORD index = 0;
    int size = sizeof(index);
    EnterCriticalSection(&engine->lock);
    int result = engine->transport == INVALID_SOCKET ? SOCKET_ERROR :
        getsockopt(engine->transport, IPPROTO_IP, IP_UNICAST_IF, (char*)&index, &size);
    LeaveCriticalSection(&engine->lock);
    /* IP_UNICAST_IF is set in network order but getsockopt returns host order. */
    return result ? 0 : index;
}

int sb_engine_roam(sb_engine *engine, const char *local_address, uint32_t local_port)
{
    if (!engine || engine != active || !local_address || !local_port || local_port > 65535 || engine->stopping) { return 1; }
    host_t *local = host_create_from_string((char*)local_address, local_port);
    if (!local || local->get_family(local) != AF_INET || local->is_anyaddr(local)) { DESTROY_IF(local); return 1; }
    uint32_t address = untoh32(local->get_address(local).ptr);
    if ((address >> 24) == 127 || (address >> 16) == 0xa9fe || (address >> 28) >= 14) { local->destroy(local); return 1; }
    EnterCriticalSection(&engine->lock);
    int invalid = !engine->mobility.enabled || !engine->mobility.negotiated ? 2 :
        engine->mobility.pending ? 3 : (engine->vip && local->ip_equals(local, engine->vip)) ? 1 : 0;
    uint32_t id = engine->status.ike_id;
    LeaveCriticalSection(&engine->lock);
    if (invalid) { local->destroy(local); return invalid; }
    ike_sa_t *sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager, id);
    if (!sa) { local->destroy(local); return 4; }
    if (!sa->supports_extension(sa, EXT_MOBIKE) || sa->get_state(sa) != IKE_ESTABLISHED) {
        charon->ike_sa_manager->checkin(charon->ike_sa_manager, sa); local->destroy(local); return 2;
    }
    EnterCriticalSection(&engine->lock);
    begin_migration(engine);
    DESTROY_IF(engine->local);
    engine->local = local;
    engine->status.local_port = local_port;
    inet_ntop(AF_INET, local->get_address(local).ptr, engine->status.local_address, 64);
    /* The old transport is invalid even if another network reuses its private IP. */
    engine->force_roam = TRUE;
    LeaveCriticalSection(&engine->lock);
    /* Include NAT detection even if the new network reused the same private IP. */
    bool queued = FALSE;
    task_queue_t queues[] = { TASK_QUEUE_QUEUED, TASK_QUEUE_ACTIVE };
    for (unsigned int index = 0; index < countof(queues); ++index) {
        task_queue_t queue = queues[index];
        task_t *task;
        enumerator_t *tasks = sa->create_task_enumerator(sa, queue);
        while (tasks->enumerate(tasks, &task)) {
            if (task->get_type(task) == TASK_IKE_MOBIKE) {
                ((ike_mobike_t*)task)->dpd((ike_mobike_t*)task);
                if (queue == TASK_QUEUE_QUEUED) { queued = TRUE; }
            }
        }
        tasks->destroy(tasks);
    }
    if (!queued) {
        ike_mobike_t *task = ike_mobike_create(sa, TRUE);
        task->dpd(task);
        sa->queue_task(sa, &task->task);
    }
    status_t result = sa->roam(sa, TRUE);
    EnterCriticalSection(&engine->lock);
    engine->force_roam = FALSE;
    if (result != SUCCESS && result != NEED_MORE) { engine->mobility.pending = 0; engine->mobility.last_error = 4; }
    LeaveCriticalSection(&engine->lock);
    if (result == DESTROY_ME) { charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, sa); }
    else { charon->ike_sa_manager->checkin(charon->ike_sa_manager, sa); }
    return result == SUCCESS || result == NEED_MORE ? 0 : 4;
}

int sb_engine_attach_ip_receiver(sb_engine *engine, sb_plain_cb receive_cb, void *context)
{
    if (!engine || engine != active || !receive_cb || engine->stopping || engine->external || !engine->status.child_up) { return 1; }
    EnterCriticalSection(&engine->lock);
    engine->receive = receive_cb;
    engine->packet_context = context;
    LeaveCriticalSection(&engine->lock);
    return 0;
}

int sb_engine_rebind_udp(sb_engine *engine, const char *local_address, sb_path *path)
{
    if (!engine || engine != active || !local_address || !path || path->size != sizeof(*path) ||
        engine->external || engine->stopping || !engine->status.authenticated || !engine->status.child_up ||
        !engine->mobility.enabled || !engine->mobility.negotiated) { return 1; }
    host_t *candidate = host_create_from_string((char*)local_address, 0);
    if (!candidate || candidate->get_family(candidate) != AF_INET || candidate->is_anyaddr(candidate)) { DESTROY_IF(candidate); return 1; }
    uint32_t address = untoh32(candidate->get_address(candidate).ptr);
    if ((address >> 24) == 127 || (address >> 16) == 0xa9fe || (address >> 28) >= 14 ||
        (engine->vip && candidate->ip_equals(candidate, engine->vip))) { candidate->destroy(candidate); return 1; }
    EnterCriticalSection(&engine->lock);
    bool busy = engine->mobility.pending;
    host_t *remote = engine->remote->clone(engine->remote);
    LeaveCriticalSection(&engine->lock);
    if (busy) { candidate->destroy(candidate); remote->destroy(remote); return 3; }
    SOCKET replacement = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    NET_IFINDEX index = physical_default_interface(engine, remote->get_sockaddr(remote), local_address);
    DWORD timeout = 200;
    struct sockaddr_in bound;
    int length = sizeof(bound);
    int setup = replacement != INVALID_SOCKET &&
        pin_udp_interface(replacement, index) &&
        !setsockopt(replacement, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) &&
        !bind(replacement, candidate->get_sockaddr(candidate), *candidate->get_sockaddr_len(candidate)) &&
        !connect(replacement, remote->get_sockaddr(remote), *remote->get_sockaddr_len(remote)) &&
        !getsockname(replacement, (struct sockaddr*)&bound, &length);
    candidate->destroy(candidate);
    remote->destroy(remote);
    if (!setup) {
        if (replacement != INVALID_SOCKET) { closesocket(replacement); }
        log_message("SwanBridge: replacement UDP socket setup failed; original socket retained");
        return 4;
    }
    engine->stop_receiver = 1;
    EnterCriticalSection(&engine->lock);
    SOCKET previous = engine->transport;
    engine->transport = INVALID_SOCKET;
    if (previous != INVALID_SOCKET) { closesocket(previous); }
    LeaveCriticalSection(&engine->lock);
    if (engine->receiver && WaitForSingleObject(engine->receiver, 3000) != WAIT_OBJECT_0) {
        closesocket(replacement);
        log_message("SwanBridge: old UDP receiver did not stop; migration rejected");
        return 5;
    }
    if (engine->receiver) { CloseHandle(engine->receiver); engine->receiver = NULL; }
    EnterCriticalSection(&engine->lock);
    engine->transport = replacement;
    LeaveCriticalSection(&engine->lock);
    path->local_port = ntohs(bound.sin_port);
    inet_ntop(AF_INET, &bound.sin_addr, path->local_address, sizeof(path->local_address));
    int result = sb_engine_roam(engine, path->local_address, path->local_port);
    engine->stop_receiver = 0;
    engine->receiver = CreateThread(NULL, 0, receive_udp, engine, 0, NULL);
    if (!engine->receiver) { return 6; }
    return result;
}

int sb_engine_handoff(sb_engine *engine, sb_send_cb send_cb, sb_plain_cb receive_cb, void *context)
{
    if (!engine || !engine->status.child_up || engine->external) { return 1; }
    engine->stop_receiver = 1;
    if (WaitForSingleObject(engine->receiver, 3000) != WAIT_OBJECT_0) { return 1; }
    CloseHandle(engine->receiver);
    engine->receiver = NULL;
    engine->send = send_cb;
    engine->receive = receive_cb;
    engine->packet_context = context;
    InterlockedExchange(&engine->external, 1);
    closesocket(engine->transport);
    engine->transport = INVALID_SOCKET;
    return 0;
}

int sb_engine_send_ip(sb_engine *engine, const uint8_t *packet, uint32_t length)
{
    if (!engine || engine->stopping || !engine->status.child_up || length < 20 || length > 65535 || packet[0] >> 4 != 4) { return 1; }
    ip_packet_t *plain = ip_packet_create(chunk_clone(chunk_create((uint8_t*)packet, length)));
    if (!plain) { return 1; }
    InterlockedIncrement64((LONG64*)&engine->status.plain_tx);
    ipsec->processor->queue_outbound(ipsec->processor, plain);
    return 0;
}

int sb_engine_dns_probe(sb_engine *engine, const char *resolver, uint32_t timeout_ms)
{
    if (!engine || !engine->status.child_up) { return 1; }
    uint8_t question[] = { 0x53,0x42,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1 };
    if (!++engine->dns_id) { ++engine->dns_id; }
    htoun16(question, engine->dns_id);
    engine->dns_port = 49179;
    host_t *src = host_create_from_string(engine->status.virtual_address, engine->dns_port);
    host_t *dst = host_create_from_string((char*)resolver, 53);
    ip_packet_t *packet = dst ? ip_packet_create_udp_from_data(src, dst, chunk_create(question, sizeof(question))) : NULL;
    DESTROY_IF(src);
    DESTROY_IF(dst);
    if (!packet) { return 1; }
    ResetEvent(engine->dns_event);
    InterlockedIncrement64((LONG64*)&engine->status.plain_tx);
    ipsec->processor->queue_outbound(ipsec->processor, packet);
    return WaitForSingleObject(engine->dns_event, timeout_ms) == WAIT_OBJECT_0 ? 0 : 2;
}

void sb_engine_stop(sb_engine *engine)
{
    if (!engine || engine != active) { return; }
    /* Windows has stopped and closed its transport before this call. Reclaim
     * the same UDP tuple for DELETE without calling back into a stopped channel. */
    if (engine->external) {
        SOCKET transport = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        DWORD timeout = 200;
        if (transport != INVALID_SOCKET &&
            !setsockopt(transport, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) &&
            !bind(transport, engine->local->get_sockaddr(engine->local), *engine->local->get_sockaddr_len(engine->local)) &&
            !connect(transport, engine->remote->get_sockaddr(engine->remote), *engine->remote->get_sockaddr_len(engine->remote))) {
            engine->transport = transport;
            engine->stop_receiver = 0;
            InterlockedExchange(&engine->external, 0);
            engine->receiver = CreateThread(NULL, 0, receive_udp, engine, 0, NULL);
        } else if (transport != INVALID_SOCKET) { closesocket(transport); }
    }
    if (engine->status.ike_id && charon->controller) {
        charon->controller->terminate_ike(charon->controller, engine->status.ike_id, TRUE,
            controller_log, engine, LEVEL_CTRL, 1500);
    }
    engine->stopping = 1;
    engine->stop_receiver = 1;
    if (engine->receiver) {
        WaitForSingleObject(engine->receiver, 3000);
        CloseHandle(engine->receiver);
    }
    if (engine->transport != INVALID_SOCKET) { closesocket(engine->transport); }
    log_message("SwanBridge: stopping protocol workers");
    libcharon_deinit();
    log_message("SwanBridge: protocol workers stopped");
    lib->credmgr->remove_set(lib->credmgr, &engine->credentials->set);
    engine->credentials->destroy(engine->credentials);
    ipsec->events->unregister_listener(ipsec->events, &engine->ipsec_listener);
    libipsec_deinit();
    engine->incoming->destroy_offset(engine->incoming, offsetof(packet_t, destroy));
    library_deinit();
    DESTROY_IF(engine->vip);
    DESTROY_IF(engine->local);
    DESTROY_IF(engine->remote);
    CloseHandle(engine->dns_event);
    DeleteCriticalSection(&engine->lock);
    free(engine);
    active = NULL;
    InterlockedExchange(&reserved, 0);
    WSACleanup();
}
