/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <library.h>
#include <daemon.h>
#include <crypto/proposal/proposal.h>
#include <encoding/message.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    message_t *request;
    key_exchange_t *exchange;
    proposal_t *proposal;
    uint64_t spi;
} probe_t;

static void destroy_probe(probe_t *probe)
{
    DESTROY_IF(probe->request);
    DESTROY_IF(probe->exchange);
    DESTROY_IF(probe->proposal);
}

static bool create_probe(probe_t *probe, host_t *source, host_t *destination)
{
    rng_t *random = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
    nonce_gen_t *generator = lib->crypto->create_nonce_gen(lib->crypto);
    chunk_t nonce = chunk_empty;
    ike_sa_id_t *id;
    ke_payload_t *ke;
    nonce_payload_t *payload;
    bool ready = random && generator &&
        random->get_bytes(random, sizeof(probe->spi), (uint8_t*)&probe->spi) &&
        generator->allocate_nonce(generator, NONCE_SIZE, &nonce);
    DESTROY_IF(random);
    DESTROY_IF(generator);
    if (!ready || !probe->spi) { chunk_clear(&nonce); return FALSE; }

    probe->proposal = proposal_create_from_string(PROTO_IKE, "aes256-sha256-modp2048");
    probe->exchange = lib->crypto->create_ke(lib->crypto, MODP_2048_BIT);
    if (!probe->proposal || !probe->exchange) { chunk_clear(&nonce); return FALSE; }
    ke = ke_payload_create_from_key_exchange(PLV2_KEY_EXCHANGE, probe->exchange);
    if (!ke) { chunk_clear(&nonce); return FALSE; }

    probe->request = message_create(2, 0);
    id = ike_sa_id_create(2, probe->spi, 0, TRUE);
    probe->request->set_ike_sa_id(probe->request, id);
    id->destroy(id);
    probe->request->set_exchange_type(probe->request, IKE_SA_INIT);
    probe->request->set_request(probe->request, TRUE);
    probe->request->set_message_id(probe->request, 0);
    probe->request->set_source(probe->request, source->clone(source));
    probe->request->set_destination(probe->request, destination->clone(destination));
    probe->request->add_payload(probe->request, (payload_t*)
        sa_payload_create_from_proposal_v2(probe->proposal));
    probe->request->add_payload(probe->request, (payload_t*)ke);
    payload = nonce_payload_create(PLV2_NONCE);
    payload->set_nonce(payload, nonce);
    probe->request->add_payload(probe->request, (payload_t*)payload);
    chunk_clear(&nonce);
    return TRUE;
}

static bool matching_proposal(probe_t *probe, message_t *message)
{
    sa_payload_t *sa = (sa_payload_t*)message->get_payload(message, PLV2_SECURITY_ASSOCIATION);
    linked_list_t *proposals;
    enumerator_t *enumerator;
    proposal_t *candidate;
    bool matches = FALSE;
    if (!sa) { return FALSE; }
    proposals = sa->get_proposals(sa);
    enumerator = proposals->create_enumerator(proposals);
    while (enumerator->enumerate(enumerator, &candidate)) {
        matches |= probe->proposal->matches(probe->proposal, candidate, PROPOSAL_SKIP_PRIVATE);
    }
    enumerator->destroy(enumerator);
    proposals->destroy_offset(proposals, offsetof(proposal_t, destroy));
    return matches;
}

static message_t *parse_packet(packet_t *packet)
{
    message_t *message = message_create_from_packet(packet);
    if (message->parse_header(message) != SUCCESS ||
        message->parse_body(message, NULL) != SUCCESS) {
        message->destroy(message);
        return NULL;
    }
    return message;
}

static void report(char const *outcome, char const *address, unsigned port,
    unsigned sent, unsigned received, unsigned notifications, bool accepted)
{
    printf("{\"Outcome\":\"%s\",\"CoreVersion\":\"%s\","
        "\"ServerIPv4\":\"%s\",\"LocalPort\":%u,\"RequestBytes\":%u,"
        "\"ResponseBytes\":%u,\"Notification\":%u,"
        "\"Proposal\":\"aes256-sha256-modp2048\",\"SaInitAccepted\":%s,"
        "\"PeerAuthenticated\":false,\"ChildSaEstablished\":false,"
        "\"VpnFunctionAccepted\":false}\n",
        outcome, VERSION, address, port, sent, received, notifications,
        accepted ? "true" : "false");
}

static int self_test(void)
{
    probe_t probe = {0};
    packet_t *packet = NULL;
    message_t *parsed = NULL;
    host_t *source = host_create_from_string("192.0.2.10", 49152);
    host_t *destination = host_create_from_string("192.0.2.1", 500);
    bool ready = create_probe(&probe, source, destination);
    unsigned length = 0;
    if (ready && probe.request->generate(probe.request, NULL, &packet) == SUCCESS) {
        length = packet->get_data(packet).len;
        parsed = parse_packet(packet);
        packet = NULL;
    }
    ready = parsed && parsed->get_request(parsed) &&
        parsed->get_initiator_spi(parsed) == probe.spi && matching_proposal(&probe, parsed);
    DESTROY_IF(parsed);
    DESTROY_IF(packet);
    source->destroy(source);
    destination->destroy(destination);
    destroy_probe(&probe);
    report(ready ? "PASS_OFFLINE_CODEC_AND_CRYPTO" : "SELF_TEST_FAILED", "", 0, length, 0, 0, FALSE);
    return ready ? 0 : 1;
}

static int probe_server(char const *server, unsigned timeout_ms)
{
    struct addrinfo hints = {0}, *addresses = NULL;
    struct sockaddr_in local;
    int local_length = sizeof(local);
    SOCKET transport = INVALID_SOCKET;
    host_t *source = NULL, *destination = NULL;
    probe_t probe = {0};
    packet_t *packet = NULL;
    message_t *response = NULL;
    char address[INET_ADDRSTRLEN] = "";
    char buffer[65535];
    char const *outcome = "LOCAL_PROBE_ERROR";
    unsigned local_port = 0, sent = 0, received = 0, notification = 0;
    bool accepted = FALSE;
    int result = 1, length, attempt;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (getaddrinfo(server, "500", &hints, &addresses) != 0) {
        outcome = "DNS_RESOLUTION_FAILED";
        goto cleanup;
    }
    inet_ntop(AF_INET, &((struct sockaddr_in*)addresses->ai_addr)->sin_addr,
        address, sizeof(address));
    transport = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (transport == INVALID_SOCKET ||
        connect(transport, addresses->ai_addr, addresses->ai_addrlen) == SOCKET_ERROR ||
        getsockname(transport, (struct sockaddr*)&local, &local_length) == SOCKET_ERROR ||
        setsockopt(transport, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR) {
        goto cleanup;
    }
    local_port = ntohs(local.sin_port);
    source = host_create_from_sockaddr((struct sockaddr*)&local);
    destination = host_create_from_sockaddr(addresses->ai_addr);
    if (!source || !destination || !create_probe(&probe, source, destination) ||
        probe.request->generate(probe.request, NULL, &packet) != SUCCESS) { goto cleanup; }
    chunk_t request = packet->get_data(packet);
    sent = request.len;

    // Retransmit one exchange, not several independent half-open SAs.
    for (attempt = 0; attempt < 3; attempt++) {
        if (send(transport, (char*)request.ptr, request.len, 0) == SOCKET_ERROR) { goto cleanup; }
        length = recv(transport, buffer, sizeof(buffer), 0);
        if (length == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAETIMEDOUT || error == WSAECONNRESET) { continue; }
            goto cleanup;
        }
        received = length;
        packet_t *incoming = packet_create();
        incoming->set_source(incoming, destination->clone(destination));
        incoming->set_destination(incoming, source->clone(source));
        incoming->set_data(incoming, chunk_clone(chunk_create((uint8_t*)buffer, length)));
        response = parse_packet(incoming);
        if (!response || response->get_major_version(response) != 2 ||
            response->get_exchange_type(response) != IKE_SA_INIT || response->get_request(response) ||
            response->get_message_id(response) != 0 || response->get_initiator_spi(response) != probe.spi) {
            outcome = "INVALID_IKE_RESPONSE";
            goto cleanup;
        }
        enumerator_t *enumerator = response->create_payload_enumerator(response);
        payload_t *payload;
        while (enumerator->enumerate(enumerator, &payload)) {
            if (payload->get_type(payload) == PLV2_NOTIFY) {
                notify_type_t type = ((notify_payload_t*)payload)->get_notify_type((notify_payload_t*)payload);
                if (type < 16384 || type == COOKIE) { notification = type; break; }
            }
        }
        enumerator->destroy(enumerator);
        if (notification) {
            outcome = notification == COOKIE ? "COOKIE_REQUIRED" : "PEER_SENT_ERROR_NOTIFICATION";
            result = 2;
            goto cleanup;
        }
        ke_payload_t *ke = (ke_payload_t*)response->get_payload(response, PLV2_KEY_EXCHANGE);
        nonce_payload_t *nonce_payload = (nonce_payload_t*)response->get_payload(response, PLV2_NONCE);
        chunk_t secret = chunk_empty, nonce = chunk_empty;
        if (nonce_payload) { nonce = nonce_payload->get_nonce(nonce_payload); }
        accepted = response->get_responder_spi(response) != 0 && matching_proposal(&probe, response) &&
            ke && ke->get_key_exchange_method(ke) == MODP_2048_BIT && nonce.len >= 16 && nonce.len <= 256 &&
            probe.exchange->set_public_key(probe.exchange, ke->get_key_exchange_data(ke)) &&
            probe.exchange->get_shared_secret(probe.exchange, &secret) && secret.len > 0;
        chunk_clear(&secret);
        chunk_clear(&nonce);
        outcome = accepted ? "IKE_SA_INIT_ACCEPTED_UNAUTHENTICATED" : "PROPOSAL_OR_KEY_EXCHANGE_REJECTED";
        result = accepted ? 0 : 2;
        goto cleanup;
    }
    outcome = "NO_IKE_SA_INIT_RESPONSE";
    result = 2;

cleanup:
    report(outcome, address, local_port, sent, received, notification, accepted);
    DESTROY_IF(response);
    DESTROY_IF(packet);
    destroy_probe(&probe);
    DESTROY_IF(source);
    DESTROY_IF(destination);
    if (transport != INVALID_SOCKET) { closesocket(transport); }
    if (addresses) { freeaddrinfo(addresses); }
    return result;
}

int main(int argc, char **argv)
{
    bool offline = argc == 2 && streq(argv[1], "--self-test");
    unsigned timeout = 3000;
    WSADATA winsock;
    char configuration[MAX_PATH];
    DWORD path_length = GetModuleFileNameA(NULL, configuration, sizeof(configuration));
    char *separator = path_length && path_length < sizeof(configuration) ? strrchr(configuration, '\\') : NULL;
    if (!separator || (size_t)(separator - configuration) + sizeof("\\probe.conf") > sizeof(configuration)) {
        return 1;
    }
    strcpy(separator + 1, "probe.conf");
    if (!offline && argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: SwanBridge.IkeProbe.exe --self-test | server [timeout-ms]\n");
        return 1;
    }
    if (argc == 3) {
        char *end;
        unsigned long value = strtoul(argv[2], &end, 10);
        if (*end || value < 500 || value > 10000) { return 1; }
        timeout = value;
    }
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) { return 1; }
    if (!library_init(configuration, "swanbridge-probe")) { WSACleanup(); return 1; }
    int result = 1;
    if (libcharon_init()) {
        if (lib->plugins->load(lib->plugins, "openssl nonce")) {
            result = offline ? self_test() : probe_server(argv[1], timeout);
        } else {
            report("CRYPTO_PLUGINS_UNAVAILABLE", "", 0, 0, 0, 0, FALSE);
        }
        libcharon_deinit();
    }
    library_deinit();
    WSACleanup();
    return result;
}
