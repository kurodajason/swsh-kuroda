// Network services of a console that is offline (issue #1, from the second patch there): nifm (no internet), ssl,
// bsd:u (sockets) and ldn:u (local wireless, no network found). Before, sm handed the game a logging stub for them,
// which answers without the objects the game asks for (CreateGeneralService, CreateRequest...): the game used a null
// session and closed when opening local wireless, Mystery Gift or internet co-op. Now those screens open and wait;
// local wireless and the GO Park settings leave with B, the Mystery Gift / internet screens keep their spinner (the
// game polls RecvFrom with no timeout and no cancel there: nothing to download without Nintendo's servers).
// Command shapes as in switchbrew (nn::nifm IGeneralService / IRequest, nn::ldn, bsd).
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../hle.h"
#include "../ipc.h"
#include "../platform.h"
static volatile int g_ldn_active;  // a wireless network is open: the game's bsd sockets are its wireless sockets (ldn:u below)
// An event the game can wait on, signalled already: nothing will ever happen, so a wait on it ends at once.
static uint32_t signalled_event(void) {
    uint32_t w, r;
    KEvent *ev = kernel_create_event_pair(&w, &r);
    pthread_mutex_lock(&g_klock);
    kernel_signal(ev);
    pthread_mutex_unlock(&g_klock);
    return r;
}

// ------------------------------------------------------------------ nifm:u
static void nifm_request(Service *s, IpcReq *req, IpcResp *resp) {
    (void)s;
    switch (req->cmd) {
    case 0: OUT(uint32_t, 0) = 1; resp_size(resp, 4); break;  // GetRequestState: free (done, not accepted)
    case 1: {  // GetResult: no internet connection (2110-0300); LARECOMP_NIFM_ERROR=<result> for experiments
        const char *e = getenv("LARECOMP_NIFM_ERROR");
        resp->result = e && *e ? (uint32_t)strtoul(e, NULL, 0) : MAKE_RESULT(110, 300);
        break;
    }
    case 2:  // GetSystemEventReadableHandles: two events
        resp->copy_handles[resp->ncopy++] = signalled_event();
        resp->copy_handles[resp->ncopy++] = signalled_event();
        break;
    case 4: break;  // Submit: done at once (GetRequestState)
    default: LOG("[nifm] IRequest cmd %u (ok)\n", req->cmd);
    }
}

static void nifm_general(Service *s, IpcReq *req, IpcResp *resp) {
    (void)s;
    switch (req->cmd) {
    case 1: memset(resp->data, 0, 4); resp_size(resp, 4); break;                               // GetClientId
    case 4: ipc_return_object(resp, service_new("IRequest", nifm_request, NULL)); break;      // CreateRequest
    case 18: memset(resp->data, 0, 4); resp_size(resp, 4); break;                              // GetInternetConnectionStatus
    default: LOG("[nifm] IGeneralService cmd %u (ok)\n", req->cmd);
    }
}

SERVICE("nifm:u", nifm_u) {
    (void)s;
    if (req->cmd == 5) ipc_return_object(resp, service_new("IGeneralService", nifm_general, NULL));  // CreateGeneralService
    else LOG("[nifm] nifm:u cmd %u (ok)\n", req->cmd);
}

// ------------------------------------------------------------------ ssl (no TLS)
static void ssl_context(Service *s, IpcReq *req, IpcResp *resp) {
    (void)s;
    LOG("[ssl] ISslContext cmd %u (ok, no TLS)\n", req->cmd);
    memset(resp->data, 0, 0x10);
    resp_size(resp, 0x10);
}

SERVICE("ssl", ssl) {
    (void)s;
    if (req->cmd == 0) ipc_return_object(resp, service_new("ISslContext", ssl_context, NULL));  // CreateContext
    else LOG("[ssl] cmd %u (ok)\n", req->cmd);
}

// ------------------------------------------------------------------ bsd:u (sockets)
// With no wireless network open: setting up succeeds, a new socket fails with ENETDOWN and a receive returns one
// zero byte. With one open (g_ldn_active, ldn:u below) sockets succeed and nothing ever arrives.
SERVICE("bsd:u", bsd_u) {
    (void)s;
    static int bsd_logged, next_fd = 100;
    if (bsd_logged < 300) { bsd_logged++; LOG("[bsd] cmd %u%s\n", req->cmd, g_ldn_active ? " (wireless)" : ""); }
    switch (req->cmd) {
    case 2:  // Socket
    case 3:  // SocketExempt
        if (g_ldn_active) { OUT(int32_t, 0) = next_fd++; OUT(int32_t, 4) = 0; }
        else { OUT(int32_t, 0) = -1; OUT(int32_t, 4) = 100; }  // ENETDOWN (Linux errno values, switchbrew)
        resp_size(resp, 8);
        break;
    case 5:  // Select
    case 6:  // Poll
    case 8:  // Recv
    case 9:  // RecvFrom
        if (g_ldn_active) {  // nothing arrives: "would block" after a short wait, so polling loops don't spin
            plat_sleep_until_ns(plat_now_ns() + 5000000ull);
            OUT(int32_t, 0) = (req->cmd == 5 || req->cmd == 6) ? 0 : -1;
            OUT(int32_t, 4) = (req->cmd == 5 || req->cmd == 6) ? 0 : 11;  // EAGAIN
            resp_size(resp, 8);
        } else if (req->cmd == 9) {
            OUT(int32_t, 0) = 1;
            OUT(int32_t, 4) = 0;
            resp_size(resp, 8);
        } else {
            LOG("[bsd] bsd:u cmd %u (ok)\n", req->cmd);
        }
        break;
    default:
        if (g_ldn_active && req->cmd > 1) { OUT(int32_t, 0) = 0; OUT(int32_t, 4) = 0; resp_size(resp, 8); }  // success
        else LOG("[bsd] bsd:u cmd %u (ok)\n", req->cmd);
    }
}

// States (switchbrew "LDN services"): 0 None, 1 Initialized, 2 AccessPoint, 3 AccessPointCreated, 4 Station,
// 5 StationConnected, 6 Error
typedef struct { int state; } Ldn;

static void ldn_set_state(Ldn *u, int st) {
    if (u) u->state = st;
    g_ldn_active = st >= 2;
}

// nn::ldn::NetworkInfo (0x480 bytes; Switchbrew / Ryujinx layout) of a network with only us in it
static void ldn_fill_network_info(uint8_t *p) {
    memset(p, 0, 0x480);
    p[0x20] = 0x02, p[0x25] = 0x01;                      // CommonNetworkInfo (0x20): bssid
    p[0x26] = 8, memcpy(p + 0x27, "swsh-ldn", 8);        // ssid
    p[0x48] = 6;                                          // channel
    p[0x4A] = 3;                                          // link level
    p[0x4B] = 2;                                          // network type: LDN
    p[0x60] = 1;                                          // LdnNetworkInfo (0x50): security mode
    p[0x66] = 8, p[0x67] = 1;                             // max nodes, node count
    uint8_t *n = p + 0x68;                                // node 0 (0x40 bytes): us
    uint32_t ip = 0x0A730001;                             // 10.115.0.1
    memcpy(n, &ip, 4);
    n[4] = 0x02, n[9] = 0x01;                             // mac
    n[0xA] = 0, n[0xB] = 1;                               // node id, connected
    memcpy(n + 0xC, "Player", 6);                         // user name
    n[0x2E] = 1;                                          // local communication version
}

static void ldn_user(Service *s, IpcReq *req, IpcResp *resp) {
    Ldn *u = s->state;
    LOG("[ldn] cmd %u (state %d)\n", req->cmd, u ? u->state : -1);
    switch (req->cmd) {
    case 0: OUT(uint32_t, 0) = u ? (uint32_t)u->state : 0; resp_size(resp, 4); break;  // GetState
    case 1: {                                                                           // GetNetworkInfo
        IpcBuf *b = out_buf(req, 0);
        if (b && b->size >= 0x480) ldn_fill_network_info((uint8_t *)(uintptr_t)b->addr);
        break;
    }
    case 2: OUT(uint32_t, 0) = 0x0A730001; OUT(uint32_t, 4) = 0xFFFF0000; resp_size(resp, 8); break;  // GetIpv4Address
    case 3: OUT(int16_t, 0) = 0; resp_size(resp, 4); break;                             // GetDisconnectReason: none
    case 100: resp->copy_handles[resp->ncopy++] = signalled_event(); break;             // AttachStateChangeEvent
    case 102: OUT(uint16_t, 0) = 0; resp_size(resp, 4); break;                          // Scan: no network found
    case 200: ldn_set_state(u, 2); break;                                               // OpenAccessPoint
    case 201: ldn_set_state(u, 1); break;                                               // CloseAccessPoint
    case 202:                                                                           // CreateNetwork
    case 203: ldn_set_state(u, 3); break;                                               // CreateNetworkPrivate
    case 204: ldn_set_state(u, 2); break;                                               // DestroyNetwork
    case 400:  // Initialize (older firmware)
    case 402:  // Initialize
    case 403:  // InitializeSystem2
        ldn_set_state(u, 1);
        break;
    case 401: ldn_set_state(u, 0); break;                                               // Finalize
    default: LOG("[ldn] IUserLocalCommunicationService cmd %u (ok, no wireless)\n", req->cmd);
    }
}

SERVICE("ldn:u", ldn_u) {
    (void)s;
    if (req->cmd == 0) ipc_return_object(resp, service_new("IUserLocalCommunicationService", ldn_user, calloc(1, sizeof(Ldn))));
    else LOG("[ldn] ldn:u cmd %u (ok)\n", req->cmd);
}
