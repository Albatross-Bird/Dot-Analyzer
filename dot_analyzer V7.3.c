/*
 * Dot Analyzer  (Rev 6)
 *
 * Analyzes PGM images of dispensed fluid dots on a substrate.
 * Two measurement modes: Bounding Box and Body Detection (morphological).
 * Reports diameter, circularity, XY grid offset, and missed dots for every image.
 * Supports rectangular and staggered (hex) grid patterns.
 * Resizable window with aspect-ratio-preserving live preview, zoom/pan, grid overlay, crosshairs.
 *
 * BUILD:
 *   windres dot_analyzer.rc -o dot_analyzer_res.o
 *   gcc dot_analyzer.c dot_analyzer_res.o -o "Dot Analyzer.exe" ^
 *       -lgdi32 -lcomdlg32 -lcomctl32 -lole32 -lshell32 -lshlwapi ^
 *       -mwindows -O2
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <time.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* ===== DYNAMIC NPCAP LOADING ===== */
/* We load wpcap.dll at runtime so Dot Analyzer works even without Npcap installed.
   Record Mode requires Npcap; analysis features do not. */

/* Minimal pcap type definitions (avoids requiring pcap.h / Npcap SDK to build) */
typedef void pcap_t;
typedef unsigned int bpf_u_int32;
#define PCAP_ERRBUF_SIZE 256
#define PCAP_NETMASK_UNKNOWN 0xFFFFFFFF

struct pcap_pkthdr { struct timeval ts; unsigned int caplen; unsigned int len; };
struct bpf_program { unsigned int bf_len; void *bf_insns; };

struct pcap_addr {
    struct pcap_addr *next;
    struct sockaddr *addr;
    struct sockaddr *netmask;
    struct sockaddr *broadaddr;
    struct sockaddr *dstaddr;
};
typedef struct pcap_if {
    struct pcap_if *next;
    char *name;
    char *description;
    struct pcap_addr *addresses;
    unsigned int flags;
} pcap_if_t;

/* Function pointer types */
typedef int   (*pfn_findalldevs)(pcap_if_t **, char *);
typedef void  (*pfn_freealldevs)(pcap_if_t *);
typedef pcap_t *(*pfn_open_live)(const char *, int, int, int, char *);
typedef int   (*pfn_next_ex)(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
typedef int   (*pfn_compile)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
typedef int   (*pfn_setfilter)(pcap_t *, struct bpf_program *);
typedef void  (*pfn_freecode)(struct bpf_program *);
typedef void  (*pfn_close)(pcap_t *);
typedef char *(*pfn_geterr)(pcap_t *);

static HMODULE g_wpcap_dll = NULL;
static pfn_findalldevs p_findalldevs;
static pfn_freealldevs p_freealldevs;
static pfn_open_live   p_open_live;
static pfn_next_ex     p_next_ex;
static pfn_compile     p_compile;
static pfn_setfilter   p_setfilter;
static pfn_freecode    p_freecode;
static pfn_close       p_close;
static pfn_geterr      p_geterr;

static int load_npcap(void) {
    if (g_wpcap_dll) return 1;
    /* Npcap installs to System32\Npcap - add to DLL search path */
    char sysdir[MAX_PATH];
    if (GetSystemDirectoryA(sysdir, MAX_PATH)) {
        char npcap_dir[MAX_PATH];
        snprintf(npcap_dir, MAX_PATH, "%s\\Npcap", sysdir);
        SetDllDirectoryA(npcap_dir);
    }
    g_wpcap_dll = LoadLibraryA("wpcap.dll");
    if (!g_wpcap_dll) return 0;
    p_findalldevs = (pfn_findalldevs)GetProcAddress(g_wpcap_dll, "pcap_findalldevs");
    p_freealldevs = (pfn_freealldevs)GetProcAddress(g_wpcap_dll, "pcap_freealldevs");
    p_open_live   = (pfn_open_live)  GetProcAddress(g_wpcap_dll, "pcap_open_live");
    p_next_ex     = (pfn_next_ex)    GetProcAddress(g_wpcap_dll, "pcap_next_ex");
    p_compile     = (pfn_compile)    GetProcAddress(g_wpcap_dll, "pcap_compile");
    p_setfilter   = (pfn_setfilter)  GetProcAddress(g_wpcap_dll, "pcap_setfilter");
    p_freecode    = (pfn_freecode)   GetProcAddress(g_wpcap_dll, "pcap_freecode");
    p_close       = (pfn_close)      GetProcAddress(g_wpcap_dll, "pcap_close");
    p_geterr      = (pfn_geterr)     GetProcAddress(g_wpcap_dll, "pcap_geterr");
    if (!p_findalldevs||!p_open_live||!p_next_ex||!p_compile||!p_setfilter||!p_close)
    { FreeLibrary(g_wpcap_dll); g_wpcap_dll=NULL; return 0; }
    return 1;
}

/* GVSP constants */
#define GVSP_HDR_SZ     8
#define GVSP_FMT_LEADER  0x01
#define GVSP_FMT_DATA    0x03
#define GVSP_FMT_TRAILER 0x02

#define REC_WIDTH   1280
#define REC_HEIGHT  1024
#define REC_FRAME_SZ (REC_WIDTH * REC_HEIGHT)

/* Recording states */
#define REC_IDLE        0
#define REC_DISCOVERING 1
#define REC_RECORDING   2
#define REC_STOPPING    3

/* Custom window message for recording status updates */
#define WM_REC_STATUS   (WM_APP + 100)
#define WM_REC_SAVED    (WM_APP + 101)

/* ===== CONSTANTS ===== */
#define MAX_BLOBS       4096
#define MAX_PATH_LEN    1024
#define MAX_FILES       2048
#define BORDER_PAD      2
#define FONT_W          5
#define FONT_H          7
#define MERGE_RATIO     1.85
#define PI              3.14159265358979323846
#define CONFIG_FILENAME L"dot_analyzer.cfg"

/* Layout */
#define LEFT_W      480
#define MARGIN      10
#define MIN_WIN_W   960
#define MIN_WIN_H   720

/* Modes */
#define MODE_BBOX   0
#define MODE_BODY   1

/* ===== GUI IDs ===== */
#define ID_BTN_BROWSE       101
#define ID_BTN_PROCESS      102
#define ID_EDIT_FOLDER      103
#define ID_EDIT_PXMM        104
#define ID_SLIDER_THRESH    105
#define ID_EDIT_THRESH      106
#define ID_CHECK_AUTO       107
#define ID_PROGRESS         108
#define ID_STATUS           109
#define ID_SLIDER_MINAREA   110
#define ID_EDIT_MINAREA     111
#define ID_PREVIEW          112
#define ID_LABEL_PREVIEW    113
#define ID_COMBO_MODE       114
#define ID_SLIDER_EROSION   115
#define ID_EDIT_EROSION     116
#define ID_BTN_PREV         117
#define ID_BTN_NEXT         118
#define ID_LABEL_IMGNUM     119
#define ID_CHECK_CROSS      120
#define ID_CHECK_GRID       121
#define ID_BTN_ZOOM         122
#define ID_BTN_ZOOMRESET    123
#define ID_LABEL_THRESH     124
#define ID_LABEL_MINAREA    125
#define ID_LABEL_EROSION    126

/* Record Mode IDs */
#define ID_COMBO_IFACE      130
#define ID_BTN_REFRESH      131
#define ID_BTN_RECORD       132
#define ID_EDIT_OUTFOLDER   133
#define ID_BTN_BROWSE_OUT   134
#define ID_EDIT_STABLE_SEC  135
#define ID_LABEL_REC_STATUS 136
#define ID_EDIT_MAD_THRESH  137
#define ID_COMBO_GRIDPAT    138

/* Grid pattern types */
#define GRIDPAT_RECT     0
#define GRIDPAT_STAGGERED 1

#define TIMER_PREVIEW       1
#define TIMER_DELAY_MS      120

/* ===== DATA STRUCTURES ===== */
typedef struct {
    int label, area;
    int min_x, min_y, max_x, max_y;
    int bb_w, bb_h, diameter_px;
    double diameter_mm;
    int cx, cy;
    int merged;
    int body_area;
    double body_cx, body_cy;
    double body_major_px, body_minor_px, body_diameter_mm;
    int body_min_x, body_min_y, body_max_x, body_max_y;
    double circularity_raw, circularity_body;
    int grid_row, grid_col;
    double offset_x_mm, offset_y_mm;
    double offset_total_px;
    int grid_valid;
} blob_t;

typedef struct { uint8_t *pixels; int width, height, maxval; } pgm_image_t;
typedef struct { double spacing_x, spacing_y, angle; double origin_x, origin_y; int valid; int staggered; double stagger_y; } grid_params_t;
typedef struct { double sum, sum_sq, min_val, max_val; int count; double *values; int values_cap; } stats_t;
typedef struct { int dx, dy; } offset_t;

/* ===== GLOBALS ===== */
static HWND g_hwnd;
static HWND g_edit_folder, g_edit_pxmm;
static HWND g_combo_mode;
static HWND g_slider_thresh, g_edit_thresh, g_label_thresh;
static HWND g_slider_minarea, g_edit_minarea, g_label_minarea;
static HWND g_slider_erosion, g_edit_erosion, g_label_erosion;
static HWND g_check_auto, g_check_cross, g_check_grid;
static HWND g_combo_gridpat;
static HWND g_progress, g_status;
static HWND g_preview_panel, g_label_preview, g_label_imgnum;
static HWND g_btn_prev, g_btn_next, g_btn_zoom, g_btn_zoomreset;
static HINSTANCE g_hinst;

static pgm_image_t g_preview_img = {0};
static uint8_t *g_preview_rgb = NULL;
static int g_preview_valid = 0;
static int g_preview_index = 0, g_preview_nfiles = 0;
static char g_preview_files[MAX_FILES][MAX_PATH_LEN];

/* Preview analysis cache */
static blob_t g_preview_blobs[MAX_BLOBS];
static int g_preview_nblobs = 0;
static grid_params_t g_preview_gp = {0};

/* Zoom state */
static int g_zoom_active = 0;
static double g_zoom = 1.0;
static double g_pan_x = 0.0, g_pan_y = 0.0; /* image-pixel offset from center */
static int g_dragging = 0;
static int g_drag_mx, g_drag_my;
static double g_drag_px, g_drag_py;

/* Tooltip for dot hover info */
static HWND g_tooltip = NULL;
static int g_hover_blob_idx = -1;

/* Minimum detected blob area in current preview */
static int g_preview_min_area_detected = 0;

/* Flag to suppress edit→slider feedback loops */
static int g_updating = 0;

/* ===== RECORD MODE STATE ===== */
static void scan_folder_for_preview(void);  /* forward declaration */
static HWND g_combo_iface, g_btn_refresh, g_btn_record;
static HWND g_edit_outfolder, g_edit_stable_sec, g_edit_mad_thresh, g_label_rec_status;
static int g_rec_state = REC_IDLE;
static HANDLE g_rec_thread = NULL;
static CRITICAL_SECTION g_rec_cs;
static volatile int g_rec_stop = 0;
static int g_rec_save_count = 0;

/* Interface list storage */
#define MAX_IFACES 32
static char g_iface_names[MAX_IFACES][512];
static char g_iface_descs[MAX_IFACES][256];
static int g_iface_count = 0;

/* Recording thread parameters (set before thread start, read-only in thread) */
static char g_rec_iface[512];
static char g_rec_outdir[MAX_PATH_LEN];
static double g_rec_stable_sec;
static double g_rec_mad_thresh;

/* ===== RECORDING THREAD ===== */

static void rec_set_status(const wchar_t *msg) {
    /* Post message to main window to update status (thread-safe) */
    wchar_t *buf = (wchar_t *)malloc(512 * sizeof(wchar_t));
    if (buf) { wcsncpy(buf, msg, 511); buf[511] = 0;
        PostMessageW(g_hwnd, WM_REC_STATUS, 0, (LPARAM)buf); }
}

static void rec_notify_saved(int count) {
    PostMessageW(g_hwnd, WM_REC_SAVED, (WPARAM)count, 0);
}

static double compute_mad(const uint8_t *a, const uint8_t *b, uint32_t size) {
    long long total = 0;
    /* Sample every 4th pixel for speed on large frames */
    uint32_t samples = 0;
    for (uint32_t i = 0; i < size; i += 4) {
        int d = (int)a[i] - (int)b[i];
        total += (d < 0) ? -d : d;
        samples++;
    }
    return (double)total / samples;
}

/* Flip image buffer about both X and Y axes (equivalent to 180° rotation).
   Corrects the mirrored orientation from the GVSP camera stream. */
static void flip_frame_xy(uint8_t *buf, int width, int height) {
    int half = (width * height) / 2;
    for (int i = 0; i < half; i++) {
        int mirror = width * height - 1 - i;
        uint8_t tmp = buf[i];
        buf[i] = buf[mirror];
        buf[mirror] = tmp;
    }
}

static DWORD WINAPI recording_thread(LPVOID param) {
    (void)param;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* -- Phase 1: Open interface -- */
    rec_set_status(L"Opening interface...");
    pcap_t *handle = p_open_live(g_rec_iface, 65535, 1, 10, errbuf);
    if (!handle) {
        wchar_t msg[512]; swprintf(msg, 512, L"Cannot open interface: %hs", errbuf);
        rec_set_status(msg);
        EnterCriticalSection(&g_rec_cs); g_rec_state = REC_IDLE; LeaveCriticalSection(&g_rec_cs);
        return 1;
    }
    
    /* -- Phase 2: Auto-discover GVSP stream -- */
    rec_set_status(L"Discovering camera stream (ensure MYD is streaming)...");
    
    char discovered_ip[64] = "";
    uint16_t discovered_port = 0;
    int found = 0;
    time_t disc_start = time(NULL);
    
    while (!found && !g_rec_stop && (time(NULL) - disc_start < 15)) {
        struct pcap_pkthdr *hdr;
        const unsigned char *pkt;
        int res = p_next_ex(handle, &hdr, &pkt);
        if (res <= 0) continue;
        if (hdr->caplen < 50) continue;
        
        const unsigned char *ip = pkt + 14;
        if ((ip[0] >> 4) != 4 || ip[9] != 17) continue;
        int ihl = (ip[0] & 0x0F) * 4;
        const unsigned char *udp = ip + ihl;
        uint16_t udp_len = (udp[4] << 8) | udp[5];
        if (udp_len < 8 + GVSP_HDR_SZ) continue;
        uint16_t payload_len = udp_len - 8;
        const unsigned char *gvsp = udp + 8;
        
        if (payload_len >= GVSP_HDR_SZ && gvsp[4] == GVSP_FMT_LEADER &&
            gvsp[6] == 0 && gvsp[7] == 0) {
            /* Found a GVSP leader! Record source IP and dest port */
            snprintf(discovered_ip, sizeof(discovered_ip), "%d.%d.%d.%d",
                     ip[12], ip[13], ip[14], ip[15]);
            discovered_port = (udp[2] << 8) | udp[3];
            
            /* Wait for a few more leaders to confirm */
            int confirm = 0;
            time_t conf_start = time(NULL);
            while (confirm < 3 && !g_rec_stop && (time(NULL) - conf_start < 3)) {
                res = p_next_ex(handle, &hdr, &pkt);
                if (res <= 0) continue;
                if (hdr->caplen < 50) continue;
                const unsigned char *ip2 = pkt + 14;
                if ((ip2[0]>>4)!=4||ip2[9]!=17) continue;
                int ihl2=(ip2[0]&0x0F)*4;
                const unsigned char *udp2=ip2+ihl2;
                uint16_t dp2=(udp2[2]<<8)|udp2[3];
                if (dp2 != discovered_port) continue;
                uint16_t ul2=(udp2[4]<<8)|udp2[5];
                if (ul2<8+GVSP_HDR_SZ) continue;
                const unsigned char *g2=udp2+8;
                if (g2[4]==GVSP_FMT_LEADER) confirm++;
            }
            if (confirm >= 3) found = 1;
        }
    }
    
    if (g_rec_stop) { p_close(handle); 
        EnterCriticalSection(&g_rec_cs); g_rec_state=REC_IDLE; LeaveCriticalSection(&g_rec_cs); return 0; }
    
    if (!found) {
        rec_set_status(L"No camera stream found. Is MYD streaming?");
        p_close(handle);
        EnterCriticalSection(&g_rec_cs); g_rec_state = REC_IDLE; LeaveCriticalSection(&g_rec_cs);
        return 1;
    }
    
    /* Apply BPF filter */
    {   char filt[256];
        snprintf(filt, sizeof(filt), "udp and src host %s and dst port %d", discovered_ip, discovered_port);
        struct bpf_program fp;
        if (p_compile(handle, &fp, filt, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            p_setfilter(handle, &fp);
            p_freecode(&fp);
        }
    }
    
    {   wchar_t msg[256]; swprintf(msg, 256, L"Recording from %hs port %d — waiting for stable frames...",
            discovered_ip, discovered_port);
        rec_set_status(msg); }
    
    EnterCriticalSection(&g_rec_cs); g_rec_state = REC_RECORDING; LeaveCriticalSection(&g_rec_cs);
    
    /* -- Phase 3: Capture loop with stability detection -- */
    uint8_t *frame_buf = (uint8_t *)malloc(REC_FRAME_SZ);
    uint8_t *prev_buf  = (uint8_t *)malloc(REC_FRAME_SZ);
    if (!frame_buf || !prev_buf) {
        free(frame_buf); free(prev_buf); p_close(handle);
        rec_set_status(L"Memory allocation failed");
        EnterCriticalSection(&g_rec_cs); g_rec_state=REC_IDLE; LeaveCriticalSection(&g_rec_cs);
        return 1;
    }
    
    uint32_t cursor = 0;
    uint16_t cur_block = 0;
    int have_prev = 0;
    int stable_count = 0;
    int stable_saved = 0;
    int save_count = 0;
    int frames_seen = 0;
    
    /* ~60 fps camera */
    int stable_frames_needed = (int)(g_rec_stable_sec * 60.0);
    if (stable_frames_needed < 2) stable_frames_needed = 2;
    double mad_threshold = g_rec_mad_thresh;
    
    /* Diagnostic counter for periodic status updates */
    int diag_counter = 0;
    
    while (!g_rec_stop) {
        struct pcap_pkthdr *hdr;
        const unsigned char *pkt;
        int res = p_next_ex(handle, &hdr, &pkt);
        if (res <= 0) continue;
        if (hdr->caplen < 50) continue;
        
        const unsigned char *ip = pkt + 14;
        if ((ip[0]>>4)!=4||ip[9]!=17) continue;
        int ihl=(ip[0]&0x0F)*4;
        const unsigned char *udp=ip+ihl;
        uint16_t udp_len=(udp[4]<<8)|udp[5];
        if (udp_len < 8+GVSP_HDR_SZ) continue;
        uint16_t payload_len = udp_len - 8;
        const unsigned char *gvsp = udp+8;
        
        uint8_t fmt = gvsp[4];
        uint16_t blk = (gvsp[2]<<8)|gvsp[3];
        
        switch (fmt) {
        case GVSP_FMT_LEADER:
            cursor = 0;
            cur_block = blk;
            frames_seen++;
            break;
            
        case GVSP_FMT_DATA:
            if (blk != cur_block) break;
            { uint16_t dlen = payload_len - GVSP_HDR_SZ;
              const unsigned char *dptr = gvsp + GVSP_HDR_SZ;
              if (cursor + dlen <= (uint32_t)REC_FRAME_SZ) {
                  memcpy(&frame_buf[cursor], dptr, dlen);
                  cursor += dlen;
              } else {
                  uint32_t space = REC_FRAME_SZ - cursor;
                  if (space > 0) { memcpy(&frame_buf[cursor], dptr, space); cursor = REC_FRAME_SZ; }
              }
            }
            break;
            
        case GVSP_FMT_TRAILER:
            if (cursor >= (uint32_t)REC_FRAME_SZ) {
                /* Complete frame */
                if (have_prev) {
                    double mad = compute_mad(frame_buf, prev_buf, REC_FRAME_SZ);
                    diag_counter++;
                    
                    /* Report MAD every ~60 frames (roughly 1 second) */
                    if (diag_counter % 60 == 0) {
                        wchar_t msg[256];
                        swprintf(msg, 256, L"MAD=%.1f (thresh=%.1f) | %d seen, %d saved | stable=%d/%d | %hs:%d",
                                 mad, mad_threshold, frames_seen, save_count,
                                 stable_count, stable_frames_needed,
                                 discovered_ip, discovered_port);
                        rec_set_status(msg);
                    }
                    
                    if (mad < mad_threshold) {
                        stable_count++;
                        if (stable_count >= stable_frames_needed && !stable_saved) {
                            /* Save! */
                            char fname[MAX_PATH_LEN];
                            snprintf(fname, sizeof(fname), "%s\\capture_%04d.pgm",
                                     g_rec_outdir, save_count);
                            FILE *fp = fopen(fname, "wb");
                            if (fp) {
                                /* Flip a copy to correct camera mirror orientation */
                                uint8_t *flip_buf = (uint8_t *)malloc(REC_FRAME_SZ);
                                if (flip_buf) {
                                    for (int i = 0; i < REC_FRAME_SZ; i++)
                                        flip_buf[i] = frame_buf[REC_FRAME_SZ - 1 - i];
                                    fprintf(fp, "P5\n%d %d\n255\n", REC_WIDTH, REC_HEIGHT);
                                    fwrite(flip_buf, 1, REC_FRAME_SZ, fp);
                                    free(flip_buf);
                                } else {
                                    /* Fallback: save unflipped */
                                    fprintf(fp, "P5\n%d %d\n255\n", REC_WIDTH, REC_HEIGHT);
                                    fwrite(frame_buf, 1, REC_FRAME_SZ, fp);
                                }
                                fclose(fp);
                                save_count++;
                                rec_notify_saved(save_count);
                                wchar_t msg[256];
                                swprintf(msg, 256, L"Saved capture_%04d.pgm (%d total) — stream %hs:%d",
                                         save_count - 1, save_count, discovered_ip, discovered_port);
                                rec_set_status(msg);
                            }
                            stable_saved = 1;
                        }
                    } else {
                        stable_count = 0;
                        stable_saved = 0;
                    }
                }
                memcpy(prev_buf, frame_buf, REC_FRAME_SZ);
                have_prev = 1;
            }
            break;
        }
    }
    
    free(frame_buf);
    free(prev_buf);
    p_close(handle);
    
    {   wchar_t msg[256]; swprintf(msg, 256, L"Stopped. Saved %d frames from %d seen.", save_count, frames_seen);
        rec_set_status(msg); }
    
    EnterCriticalSection(&g_rec_cs); g_rec_state = REC_IDLE; LeaveCriticalSection(&g_rec_cs);
    g_rec_save_count = save_count;
    return 0;
}

static void refresh_interfaces(void) {
    if (!load_npcap()) {
        SendMessageW(g_combo_iface, CB_RESETCONTENT, 0, 0);
        SendMessageW(g_combo_iface, CB_ADDSTRING, 0, (LPARAM)L"Npcap not installed");
        SendMessageW(g_combo_iface, CB_SETCURSEL, 0, 0);
        return;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (p_findalldevs(&alldevs, errbuf) == -1) return;
    
    SendMessageW(g_combo_iface, CB_RESETCONTENT, 0, 0);
    g_iface_count = 0;
    
    pcap_if_t *d;
    for (d = alldevs; d && g_iface_count < MAX_IFACES; d = d->next) {
        strncpy(g_iface_names[g_iface_count], d->name, 511);
        
        /* Build description: name + IP if available */
        char desc[256] = "";
        if (d->description) snprintf(desc, sizeof(desc), "%s", d->description);
        else snprintf(desc, sizeof(desc), "Interface %d", g_iface_count + 1);
        
        /* Append IP address if found */
        struct pcap_addr *a;
        for (a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                char ip_str[32];
                /* Manual IP formatting to avoid inet_ntoa linkage issues */
                unsigned char *b = (unsigned char *)&sin->sin_addr;
                snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
                int len = (int)strlen(desc);
                snprintf(desc + len, sizeof(desc) - len, "  [%s]", ip_str);
                break;
            }
        }
        strncpy(g_iface_descs[g_iface_count], desc, 255);
        
        wchar_t wdesc[256];
        MultiByteToWideChar(CP_ACP, 0, desc, -1, wdesc, 256);
        SendMessageW(g_combo_iface, CB_ADDSTRING, 0, (LPARAM)wdesc);
        g_iface_count++;
    }
    
    p_freealldevs(alldevs);
    
    if (g_iface_count > 0)
        SendMessageW(g_combo_iface, CB_SETCURSEL, 0, 0);
}

static void start_recording(void) {
    if (g_rec_state != REC_IDLE) return;
    if (!load_npcap()) {
        MessageBoxW(g_hwnd, L"Npcap is not installed.\n\nInstall Npcap (https://npcap.com) to enable Record Mode.",
                     L"Npcap Required", MB_OK | MB_ICONWARNING);
        return;
    }
    
    int idx = (int)SendMessageW(g_combo_iface, CB_GETCURSEL, 0, 0);
    if (idx < 0 || idx >= g_iface_count) {
        MessageBoxW(g_hwnd, L"Select a network interface first.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    /* Get output folder */
    wchar_t wout[MAX_PATH_LEN]; char aout[MAX_PATH_LEN];
    GetWindowTextW(g_edit_outfolder, wout, MAX_PATH_LEN);
    WideCharToMultiByte(CP_ACP, 0, wout, -1, aout, MAX_PATH_LEN, NULL, NULL);
    if (strlen(aout) == 0) {
        MessageBoxW(g_hwnd, L"Select an output folder for recordings.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    CreateDirectoryA(aout, NULL);  /* ensure it exists */
    
    /* Get stability time */
    wchar_t wsec[32];
    GetWindowTextW(g_edit_stable_sec, wsec, 32);
    char asec[32];
    WideCharToMultiByte(CP_ACP, 0, wsec, -1, asec, 32, NULL, NULL);
    double sec = atof(asec);
    if (sec < 0.05) sec = 0.05;
    if (sec > 5.0) sec = 5.0;
    
    /* Get MAD threshold */
    wchar_t wmad[32];
    GetWindowTextW(g_edit_mad_thresh, wmad, 32);
    char amad[32];
    WideCharToMultiByte(CP_ACP, 0, wmad, -1, amad, 32, NULL, NULL);
    double mad_th = atof(amad);
    if (mad_th < 1.0) mad_th = 1.0;
    if (mad_th > 100.0) mad_th = 100.0;
    
    /* Copy parameters for thread */
    strncpy(g_rec_iface, g_iface_names[idx], sizeof(g_rec_iface) - 1);
    strncpy(g_rec_outdir, aout, sizeof(g_rec_outdir) - 1);
    g_rec_stable_sec = sec;
    g_rec_mad_thresh = mad_th;
    g_rec_stop = 0;
    g_rec_save_count = 0;
    
    EnterCriticalSection(&g_rec_cs);
    g_rec_state = REC_DISCOVERING;
    LeaveCriticalSection(&g_rec_cs);
    
    SetWindowTextW(g_btn_record, L"Stop Recording");
    SetWindowTextW(g_label_rec_status, L"Starting capture...");
    
    g_rec_thread = CreateThread(NULL, 0, recording_thread, NULL, 0, NULL);
    if (!g_rec_thread) {
        EnterCriticalSection(&g_rec_cs); g_rec_state = REC_IDLE; LeaveCriticalSection(&g_rec_cs);
        SetWindowTextW(g_btn_record, L"Start Recording");
        MessageBoxW(g_hwnd, L"Failed to create recording thread.", L"Error", MB_OK | MB_ICONERROR);
    }
}

static void stop_recording(void) {
    if (g_rec_state == REC_IDLE) return;
    g_rec_stop = 1;
    SetWindowTextW(g_label_rec_status, L"Stopping...");
    
    /* Wait for thread with timeout */
    if (g_rec_thread) {
        WaitForSingleObject(g_rec_thread, 5000);
        CloseHandle(g_rec_thread);
        g_rec_thread = NULL;
    }
    
    EnterCriticalSection(&g_rec_cs);
    g_rec_state = REC_IDLE;
    LeaveCriticalSection(&g_rec_cs);
    
    SetWindowTextW(g_btn_record, L"Start Recording");
    
    /* If files were saved and the output dir matches the analysis folder, refresh preview */
    if (g_rec_save_count > 0) {
        wchar_t wout[MAX_PATH_LEN], wfolder[MAX_PATH_LEN];
        GetWindowTextW(g_edit_outfolder, wout, MAX_PATH_LEN);
        GetWindowTextW(g_edit_folder, wfolder, MAX_PATH_LEN);
        if (_wcsicmp(wout, wfolder) == 0) scan_folder_for_preview();
    }
}

static void browse_output_folder(HWND hwnd) {
    BROWSEINFOW bi = {0}; bi.hwndOwner = hwnd;
    bi.lpszTitle = L"Select output folder for recorded frames";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) { wchar_t p[MAX_PATH];
        if (SHGetPathFromIDListW(pidl, p)) SetWindowTextW(g_edit_outfolder, p);
        CoTaskMemFree(pidl); }
}

/* ===== 5x7 BITMAP FONT ===== */
static const uint8_t font_5x7[][7] = {
    {0x0E,0x11,0x13,0x15,0x19,0x11,0x0E},{0x04,0x0C,0x04,0x04,0x04,0x04,0x0E},
    {0x0E,0x11,0x01,0x02,0x04,0x08,0x1F},{0x0E,0x11,0x01,0x06,0x01,0x11,0x0E},
    {0x02,0x06,0x0A,0x12,0x1F,0x02,0x02},{0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E},
    {0x06,0x08,0x10,0x1E,0x11,0x11,0x0E},{0x1F,0x01,0x02,0x04,0x08,0x08,0x08},
    {0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E},{0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C},
    {0x00,0x00,0x00,0x00,0x00,0x0C,0x0C},{0x00,0x00,0x00,0x0E,0x00,0x00,0x00},
    {0x00,0x00,0x1A,0x15,0x15,0x11,0x11},{0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x11,0x1B,0x15,0x15,0x11,0x11,0x11},{0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F},
    {0x1E,0x11,0x11,0x1E,0x14,0x12,0x11},{0x0E,0x11,0x10,0x17,0x11,0x11,0x0F},
    {0x1C,0x12,0x11,0x11,0x11,0x12,0x1C},
};
static int font_index(char c) {
    if (c>='0'&&c<='9') return c-'0';
    switch(c){case '.':return 10;case '-':return 11;case 'm':return 12;
    case ' ':return 13;case 'M':return 14;case 'E':return 15;
    case 'R':return 16;case 'G':return 17;case 'D':return 18;default:return 13;}
}

/* ===== CONFIG ===== */
static void update_auto_state(void);
static void update_mode_state(void);
static void get_config_path(wchar_t *out, int mx) {
    GetModuleFileNameW(NULL,out,mx);
    wchar_t *s=wcsrchr(out,L'\\');
    if(s) wcscpy(s+1,CONFIG_FILENAME); else wcscpy(out,CONFIG_FILENAME);
}
static void save_config(void) {
    wchar_t p[MAX_PATH],v[64]; get_config_path(p,MAX_PATH);
    FILE *f=_wfopen(p,L"w");
    if(!f) return;
    GetWindowTextW(g_edit_pxmm,v,64);
    fwprintf(f,L"px_per_mm=%s\n",v);
    /* Threshold */
    int th_val=(int)SendMessageW(g_slider_thresh,TBM_GETPOS,0,0);
    fwprintf(f,L"threshold=%d\n",th_val);
    /* Auto threshold */
    int auto_th=(SendMessageW(g_check_auto,BM_GETCHECK,0,0)==BST_CHECKED)?1:0;
    fwprintf(f,L"auto_threshold=%d\n",auto_th);
    /* Min area */
    int ma_val=(int)SendMessageW(g_slider_minarea,TBM_GETPOS,0,0);
    fwprintf(f,L"min_area=%d\n",ma_val);
    /* Erosion */
    int er_val=(int)SendMessageW(g_slider_erosion,TBM_GETPOS,0,0);
    fwprintf(f,L"erosion=%d\n",er_val);
    /* Mode */
    int mode_val=(int)SendMessageW(g_combo_mode,CB_GETCURSEL,0,0);
    fwprintf(f,L"mode=%d\n",mode_val);
    /* Grid pattern */
    int gp_val=(int)SendMessageW(g_combo_gridpat,CB_GETCURSEL,0,0);
    fwprintf(f,L"grid_pattern=%d\n",gp_val);
    /* Crosshairs */
    int cross=(SendMessageW(g_check_cross,BM_GETCHECK,0,0)==BST_CHECKED)?1:0;
    fwprintf(f,L"crosshairs=%d\n",cross);
    /* Grid overlay */
    int grid=(SendMessageW(g_check_grid,BM_GETCHECK,0,0)==BST_CHECKED)?1:0;
    fwprintf(f,L"grid_overlay=%d\n",grid);
    fclose(f);
}
static void load_config(void) {
    wchar_t p[MAX_PATH]; get_config_path(p,MAX_PATH);
    FILE *f=_wfopen(p,L"r"); if(!f) return;
    wchar_t line[128];
    while(fgetws(line,128,f)){
        wchar_t *eq=wcschr(line,L'=');
        if(!eq) continue;
        /* Strip newline from value */
        wchar_t *nl=wcschr(eq+1,L'\n');if(nl)*nl=0;
        nl=wcschr(eq+1,L'\r');if(nl)*nl=0;
        wchar_t *val=eq+1;
        int key_len=(int)(eq-line);
        if(key_len==9 && wcsncmp(line,L"px_per_mm",9)==0){
            SetWindowTextW(g_edit_pxmm,val);
        }else if(key_len==9 && wcsncmp(line,L"threshold",9)==0){
            int v=_wtoi(val);if(v>=1&&v<=254){
                SendMessageW(g_slider_thresh,TBM_SETPOS,TRUE,v);
                wchar_t tb[32];swprintf(tb,32,L"%d",v);SetWindowTextW(g_edit_thresh,tb);}
        }else if(key_len==14 && wcsncmp(line,L"auto_threshold",14)==0){
            int v=_wtoi(val);
            SendMessageW(g_check_auto,BM_SETCHECK,v?BST_CHECKED:BST_UNCHECKED,0);
        }else if(key_len==8 && wcsncmp(line,L"min_area",8)==0){
            int v=_wtoi(val);if(v>=10&&v<=2000){
                SendMessageW(g_slider_minarea,TBM_SETPOS,TRUE,v);
                wchar_t tb[32];swprintf(tb,32,L"%d",v);SetWindowTextW(g_edit_minarea,tb);}
        }else if(key_len==7 && wcsncmp(line,L"erosion",7)==0){
            int v=_wtoi(val);if(v>=1&&v<=15){
                SendMessageW(g_slider_erosion,TBM_SETPOS,TRUE,v);
                wchar_t tb[32];swprintf(tb,32,L"%d",v);SetWindowTextW(g_edit_erosion,tb);}
        }else if(key_len==4 && wcsncmp(line,L"mode",4)==0){
            int v=_wtoi(val);if(v>=0&&v<=1)
                SendMessageW(g_combo_mode,CB_SETCURSEL,v,0);
        }else if(key_len==12 && wcsncmp(line,L"grid_pattern",12)==0){
            int v=_wtoi(val);if(v>=0&&v<=1)
                SendMessageW(g_combo_gridpat,CB_SETCURSEL,v,0);
        }else if(key_len==10 && wcsncmp(line,L"crosshairs",10)==0){
            int v=_wtoi(val);
            SendMessageW(g_check_cross,BM_SETCHECK,v?BST_CHECKED:BST_UNCHECKED,0);
        }else if(key_len==12 && wcsncmp(line,L"grid_overlay",12)==0){
            int v=_wtoi(val);
            SendMessageW(g_check_grid,BM_SETCHECK,v?BST_CHECKED:BST_UNCHECKED,0);
        }
    }
    fclose(f);
    update_auto_state();
    update_mode_state();
}

/* ===== PGM I/O ===== */
static int pgm_load(const char *path, pgm_image_t *img) {
    FILE *f=fopen(path,"rb"); if(!f) return 0;
    int c1=fgetc(f),c2=fgetc(f);
    if(c1!='P'||c2!='5'){fclose(f);return 0;}
    while((c1=fgetc(f))!='\n'&&c1!='\r'&&c1!=EOF);
    if(c1=='\r'){c1=fgetc(f);if(c1!='\n')ungetc(c1,f);}
    while((c1=fgetc(f))=='#')while((c1=fgetc(f))!='\n'&&c1!=EOF);
    ungetc(c1,f);
    if(fscanf(f,"%d %d",&img->width,&img->height)!=2){fclose(f);return 0;}
    if(fscanf(f,"%d",&img->maxval)!=1){fclose(f);return 0;}
    fgetc(f);
    int sz=img->width*img->height;
    img->pixels=(uint8_t*)malloc(sz);
    if(!img->pixels){fclose(f);return 0;}
    int nr=(int)fread(img->pixels,1,sz,f);fclose(f);
    if(nr<sz)memset(img->pixels+nr,0,sz-nr);
    return 1;
}
static int pgm_save(const char *path, const pgm_image_t *img) {
    FILE *f=fopen(path,"wb"); if(!f) return 0;
    fprintf(f,"P5\n%d %d\n%d\n",img->width,img->height,img->maxval);
    fwrite(img->pixels,1,img->width*img->height,f);fclose(f);return 1;
}
static void pgm_free(pgm_image_t *img){if(img->pixels){free(img->pixels);img->pixels=NULL;}}

/* ===== IMAGE PROCESSING ===== */
static int compute_otsu(const uint8_t *px, int count) {
    int hist[256]={0}; for(int i=0;i<count;i++) hist[px[i]]++;
    double sum=0; for(int i=0;i<256;i++) sum+=(double)i*hist[i];
    double sB=0,wB=0,mx=0;int th=0;
    for(int t=0;t<256;t++){wB+=hist[t];if(wB==0)continue;
        double wF=count-wB;if(wF==0)break;sB+=(double)t*hist[t];
        double d=sB/wB-(sum-sB)/wF,v=wB*wF*d*d;if(v>mx){mx=v;th=t;}}
    return th;
}

static void fill_holes(uint8_t *bin, int w, int h) {
    uint8_t *vis=(uint8_t*)calloc(w*h,1);int *Q=(int*)malloc(w*h*sizeof(int));
    if(!vis||!Q){free(vis);free(Q);return;}
    int qh=0,qt=0;
    for(int x=0;x<w;x++){if(!bin[x]){vis[x]=1;Q[qt++]=x;}
        if(!bin[(h-1)*w+x]){vis[(h-1)*w+x]=1;Q[qt++]=(h-1)*w+x;}}
    for(int y=1;y<h-1;y++){if(!bin[y*w]){vis[y*w]=1;Q[qt++]=y*w;}
        if(!bin[y*w+w-1]){vis[y*w+w-1]=1;Q[qt++]=y*w+w-1;}}
    while(qh<qt){int i=Q[qh++];int iy=i/w,ix=i%w;
        int nb[4]={(iy>0)?i-w:-1,(iy<h-1)?i+w:-1,(ix>0)?i-1:-1,(ix<w-1)?i+1:-1};
        for(int j=0;j<4;j++){int n=nb[j];if(n>=0&&!bin[n]&&!vis[n]){vis[n]=1;Q[qt++]=n;}}}
    for(int i=0;i<w*h;i++) if(!bin[i]&&!vis[i]) bin[i]=1;
    free(vis);free(Q);
}

static int build_se(int r, offset_t *off, int mx) {
    int n=0; for(int dy=-r;dy<=r;dy++) for(int dx=-r;dx<=r;dx++)
        if(dx*dx+dy*dy<=r*r&&n<mx){off[n].dx=dx;off[n].dy=dy;n++;} return n;
}
static uint8_t *morph_erode(const uint8_t *bin,int w,int h,int r){
    uint8_t *out=(uint8_t*)calloc(w*h,1);if(!out)return NULL;
    offset_t se[512];int nse=build_se(r,se,512);
    for(int y=r;y<h-r;y++)for(int x=r;x<w-r;x++){if(!bin[y*w+x])continue;
        int ok=1;for(int k=0;k<nse&&ok;k++)if(!bin[(y+se[k].dy)*w+x+se[k].dx])ok=0;
        out[y*w+x]=ok;} return out;
}
static uint8_t *morph_dilate(const uint8_t *bin,int w,int h,int r){
    uint8_t *out=(uint8_t*)calloc(w*h,1);if(!out)return NULL;
    offset_t se[512];int nse=build_se(r,se,512);
    for(int y=0;y<h;y++)for(int x=0;x<w;x++){if(!bin[y*w+x])continue;
        for(int k=0;k<nse;k++){int nx=x+se[k].dx,ny=y+se[k].dy;
            if(nx>=0&&nx<w&&ny>=0&&ny<h)out[ny*w+nx]=1;}} return out;
}
static uint8_t *morph_open(const uint8_t *bin,int w,int h,int r){
    if(r<=0){uint8_t *c=(uint8_t*)malloc(w*h);if(c)memcpy(c,bin,w*h);return c;}
    uint8_t *e=morph_erode(bin,w,h,r);if(!e)return NULL;
    uint8_t *o=morph_dilate(e,w,h,r);free(e);return o;
}

/* Connected components with label map output */
static int find_blobs_labeled(const uint8_t *bin,int w,int h,
    blob_t *blobs,int mx_blobs,int min_area,int **out_labels){
    int *labels=(int*)calloc(w*h,sizeof(int));
    int *Q=(int*)malloc(w*h*sizeof(int));
    if(!labels||!Q){free(labels);free(Q);*out_labels=NULL;return 0;}
    int nb_out=0,lbl=0;
    for(int y=0;y<h&&nb_out<mx_blobs;y++)for(int x=0;x<w&&nb_out<mx_blobs;x++){
        int idx=y*w+x;if(!bin[idx]||labels[idx])continue;lbl++;
        int qh=0,qt=0;Q[qt++]=idx;labels[idx]=lbl;
        int area=0,bx0=x,bx1=x,by0=y,by1=y;long long sx=0,sy=0;
        while(qh<qt){int ci=Q[qh++];int cy2=ci/w,cx2=ci%w;
            area++;sx+=cx2;sy+=cy2;
            if(cx2<bx0)bx0=cx2;if(cx2>bx1)bx1=cx2;if(cy2<by0)by0=cy2;if(cy2>by1)by1=cy2;
            int nb[4]={(cy2>0)?ci-w:-1,(cy2<h-1)?ci+w:-1,(cx2>0)?ci-1:-1,(cx2<w-1)?ci+1:-1};
            for(int j=0;j<4;j++){int n=nb[j];if(n>=0&&bin[n]&&!labels[n]){labels[n]=lbl;Q[qt++]=n;}}}
        if(area>=min_area&&bx0>0&&by0>0&&bx1<w-1&&by1<h-1){
            blob_t *b=&blobs[nb_out];memset(b,0,sizeof(blob_t));
            b->label=lbl;b->area=area;b->min_x=bx0;b->min_y=by0;b->max_x=bx1;b->max_y=by1;
            b->bb_w=bx1-bx0+1;b->bb_h=by1-by0+1;
            b->diameter_px=(b->bb_w>b->bb_h)?b->bb_w:b->bb_h;
            b->cx=(int)(sx/area);b->cy=(int)(sy/area);nb_out++;}}
    free(Q);*out_labels=labels;return nb_out;
}

/* Detailed measurements: perimeter, circularity, body ellipse fit, body bbox */
static void compute_measurements(const int *labels,const uint8_t *opened,
    int w,int h,blob_t *blobs,int nblobs){
    typedef struct{int raw_perim;long long bsx,bsy;int ba;
        double mu20,mu02,mu11;int bp;int bmx0,bmy0,bmx1,bmy1;}acc_t;
    acc_t *acc=(acc_t*)calloc(nblobs,sizeof(acc_t));if(!acc)return;
    for(int i=0;i<nblobs;i++){acc[i].bmx0=w;acc[i].bmy0=h;acc[i].bmx1=0;acc[i].bmy1=0;}
    int mx_lbl=0;for(int i=0;i<nblobs;i++)if(blobs[i].label>mx_lbl)mx_lbl=blobs[i].label;
    int *l2i=(int*)malloc((mx_lbl+1)*sizeof(int));
    if(!l2i){free(acc);return;}
    memset(l2i,-1,(mx_lbl+1)*sizeof(int));
    for(int i=0;i<nblobs;i++)l2i[blobs[i].label]=i;

    /* Pass 1: areas, perimeters, body centroids, body bbox */
    for(int y=0;y<h;y++)for(int x=0;x<w;x++){
        int lb=labels[y*w+x];if(lb<=0||lb>mx_lbl)continue;
        int bi=l2i[lb];if(bi<0)continue;
        int is_b=0;
        if(x==0||labels[y*w+x-1]!=lb)is_b=1;
        else if(x==w-1||labels[y*w+x+1]!=lb)is_b=1;
        else if(y==0||labels[(y-1)*w+x]!=lb)is_b=1;
        else if(y==h-1||labels[(y+1)*w+x]!=lb)is_b=1;
        if(is_b)acc[bi].raw_perim++;
        if(opened&&opened[y*w+x]){
            acc[bi].ba++;acc[bi].bsx+=x;acc[bi].bsy+=y;
            if(x<acc[bi].bmx0)acc[bi].bmx0=x;if(x>acc[bi].bmx1)acc[bi].bmx1=x;
            if(y<acc[bi].bmy0)acc[bi].bmy0=y;if(y>acc[bi].bmy1)acc[bi].bmy1=y;
            int bb=0;
            if(x==0||!opened[y*w+x-1]||labels[y*w+x-1]!=lb)bb=1;
            else if(x==w-1||!opened[y*w+x+1]||labels[y*w+x+1]!=lb)bb=1;
            else if(y==0||!opened[(y-1)*w+x]||labels[(y-1)*w+x]!=lb)bb=1;
            else if(y==h-1||!opened[(y+1)*w+x]||labels[(y+1)*w+x]!=lb)bb=1;
            if(bb)acc[bi].bp++;
        }
    }
    for(int i=0;i<nblobs;i++){
        blobs[i].body_area=acc[i].ba;
        if(acc[i].ba>0){blobs[i].body_cx=(double)acc[i].bsx/acc[i].ba;
            blobs[i].body_cy=(double)acc[i].bsy/acc[i].ba;
            blobs[i].body_min_x=acc[i].bmx0;blobs[i].body_min_y=acc[i].bmy0;
            blobs[i].body_max_x=acc[i].bmx1;blobs[i].body_max_y=acc[i].bmy1;
        }else{blobs[i].body_cx=blobs[i].cx;blobs[i].body_cy=blobs[i].cy;
            blobs[i].body_min_x=blobs[i].min_x;blobs[i].body_min_y=blobs[i].min_y;
            blobs[i].body_max_x=blobs[i].max_x;blobs[i].body_max_y=blobs[i].max_y;}
    }

    /* Pass 2: central moments for body ellipse */
    if(opened){for(int y=0;y<h;y++)for(int x=0;x<w;x++){
        int lb=labels[y*w+x];if(lb<=0||lb>mx_lbl)continue;
        int bi=l2i[lb];if(bi<0||!opened[y*w+x])continue;
        double dx=x-blobs[bi].body_cx,dy=y-blobs[bi].body_cy;
        acc[bi].mu20+=dx*dx;acc[bi].mu02+=dy*dy;acc[bi].mu11+=dx*dy;}}

    for(int i=0;i<nblobs;i++){
        blob_t *b=&blobs[i];
        if(acc[i].raw_perim>0){double p=(double)acc[i].raw_perim;
            b->circularity_raw=4.0*PI*b->area/(p*p);if(b->circularity_raw>1.0)b->circularity_raw=1.0;}
        if(acc[i].ba>10){
            double a=(double)acc[i].ba,m20=acc[i].mu20/a,m02=acc[i].mu02/a,m11=acc[i].mu11/a;
            double diff=m20-m02,disc=sqrt(diff*diff+4.0*m11*m11);
            double l1=(m20+m02+disc)/2.0,l2=(m20+m02-disc)/2.0;if(l2<0)l2=0;
            b->body_major_px=4.0*sqrt(l1);b->body_minor_px=4.0*sqrt(l2);
            if(acc[i].bp>0){double p=(double)acc[i].bp;
                b->circularity_body=4.0*PI*a/(p*p);if(b->circularity_body>1.0)b->circularity_body=1.0;}
        }else{b->body_major_px=b->diameter_px;
            b->body_minor_px=(b->bb_w<b->bb_h)?b->bb_w:b->bb_h;
            b->circularity_body=b->circularity_raw;}
    }
    free(acc);free(l2i);
}

static void flag_merged(blob_t *blobs,int n){
    if(n<3)return;
    int *a=(int*)malloc(n*sizeof(int));if(!a)return;
    for(int i=0;i<n;i++)a[i]=blobs[i].area;
    for(int i=0;i<n-1;i++)for(int j=i+1;j<n;j++)if(a[j]<a[i]){int t=a[i];a[i]=a[j];a[j]=t;}
    int med=a[n/2];free(a);
    for(int i=0;i<n;i++){double asp=(double)blobs[i].bb_w/(double)blobs[i].bb_h;
        if(asp<1.0)asp=1.0/asp;if(asp>MERGE_RATIO||blobs[i].area>med*2.2)blobs[i].merged=1;}
}

/* Full image processing pipeline */
static int process_image_full(const pgm_image_t *img,int thresh,int min_area,
    int erosion_r,blob_t *blobs,int mx){
    int W=img->width,H=img->height,sz=W*H;
    uint8_t *bin=(uint8_t*)calloc(sz,1);if(!bin)return 0;
    for(int i=0;i<sz;i++)bin[i]=(img->pixels[i]<thresh)?1:0;
    fill_holes(bin,W,H);
    uint8_t *opened=morph_open(bin,W,H,erosion_r);
    int *labels=NULL;
    int nb=find_blobs_labeled(bin,W,H,blobs,mx,min_area,&labels);
    if(labels){compute_measurements(labels,opened,W,H,blobs,nb);free(labels);}
    flag_merged(blobs,nb);
    free(bin);if(opened)free(opened);
    return nb;
}

/* Lightweight version for fast preview */
static int process_image_light(const pgm_image_t *img,int thresh,int min_area,
    blob_t *blobs,int mx){
    int W=img->width,H=img->height,sz=W*H;
    uint8_t *bin=(uint8_t*)calloc(sz,1);if(!bin)return 0;
    for(int i=0;i<sz;i++)bin[i]=(img->pixels[i]<thresh)?1:0;
    fill_holes(bin,W,H);
    int *labels=NULL;
    int nb=find_blobs_labeled(bin,W,H,blobs,mx,min_area,&labels);
    flag_merged(blobs,nb);
    free(bin);if(labels)free(labels);
    return nb;
}

/* ===== GRID INFERENCE ===== */
static int cmp_double(const void *a,const void *b){
    double da=*(const double*)a,db=*(const double*)b;return(da>db)-(da<db);}
static double median_arr(double *a,int n){if(n<=0)return 0;
    qsort(a,n,sizeof(double),cmp_double);
    return(n%2==1)?a[n/2]:(a[n/2-1]+a[n/2])/2.0;}

static void infer_grid_params(const blob_t *blobs,int nblobs,grid_params_t *gp,int gridpat){
    gp->valid=0;gp->staggered=0;gp->stagger_y=0;
    int nc=0;double *cxs=(double*)malloc(nblobs*sizeof(double));
    double *cys=(double*)malloc(nblobs*sizeof(double));
    if(!cxs||!cys){free(cxs);free(cys);return;}
    for(int i=0;i<nblobs;i++)if(!blobs[i].merged){cxs[nc]=blobs[i].cx;cys[nc]=blobs[i].cy;nc++;}
    if(nc<4){free(cxs);free(cys);return;}

    /* Nearest-neighbor median for spacing estimate */
    double *nn_d=(double*)malloc(nc*sizeof(double));
    if(!nn_d){free(cxs);free(cys);return;}
    for(int i=0;i<nc;i++){double best=1e18;for(int j=0;j<nc;j++){if(i==j)continue;
        double d=(cxs[i]-cxs[j])*(cxs[i]-cxs[j])+(cys[i]-cys[j])*(cys[i]-cys[j]);
        if(d<best)best=d;}nn_d[i]=sqrt(best);}
    double med_nn=median_arr(nn_d,nc);free(nn_d);

    /* Sort centroids by Y */
    int *si2=(int*)malloc(nc*sizeof(int));if(!si2){free(cxs);free(cys);return;}
    for(int i=0;i<nc;i++) si2[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(cys[si2[j]]<cys[si2[i]]){int t=si2[i];si2[i]=si2[j];si2[j]=t;}

    /* Cluster into rows (Y-gap > spacing/2) */
    double gap_th=med_nn*0.5;
    int *rs=(int*)calloc(nc,sizeof(int)),*rcnt=(int*)calloc(nc,sizeof(int));
    if(!rs||!rcnt){free(cxs);free(cys);free(si2);free(rs);free(rcnt);return;}
    int nrows=1;rs[0]=0;rcnt[0]=1;
    for(int i=1;i<nc;i++){
        if(cys[si2[i]]-cys[si2[i-1]]>gap_th){nrows++;rs[nrows-1]=i;rcnt[nrows-1]=1;}
        else rcnt[nrows-1]++;}

    /* Fit line to each row with >=3 dots -> collect slopes */
    double *slopes=(double*)malloc(nrows*sizeof(double));
    if(!slopes){free(cxs);free(cys);free(si2);free(rs);free(rcnt);return;}
    int nslopes=0;
    for(int r=0;r<nrows;r++){
        if(rcnt[r]<3) continue;
        int rstart=rs[r],cnt=rcnt[r];
        double xmin=1e18,xmax=-1e18;
        for(int k=0;k<cnt;k++){int idx=si2[rstart+k];
            if(cxs[idx]<xmin)xmin=cxs[idx];if(cxs[idx]>xmax)xmax=cxs[idx];}
        if(xmax-xmin<med_nn*1.5) continue;
        double Sx=0,Sy=0,Sxy=0,Sxx=0;
        for(int k=0;k<cnt;k++){int idx=si2[rstart+k];
            Sx+=cxs[idx];Sy+=cys[idx];Sxy+=cxs[idx]*cys[idx];Sxx+=cxs[idx]*cxs[idx];}
        double denom=cnt*Sxx-Sx*Sx;
        if(fabs(denom)<1e-12) continue;
        slopes[nslopes++]=(cnt*Sxy-Sx*Sy)/denom;
    }
    if(nslopes<1){free(cxs);free(cys);free(si2);free(rs);free(rcnt);free(slopes);return;}
    double angle=atan(median_arr(slopes,nslopes));
    free(slopes); gp->angle=angle;

    /* Rotate all points to grid-aligned frame */
    double ca=cos(-angle),sna=sin(-angle);
    double *rxs=(double*)malloc(nc*sizeof(double)),*rys=(double*)malloc(nc*sizeof(double));
    if(!rxs||!rys){free(cxs);free(cys);free(si2);free(rs);free(rcnt);free(rxs);free(rys);return;}
    for(int i=0;i<nc;i++){rxs[i]=cxs[i]*ca-cys[i]*sna;rys[i]=cxs[i]*sna+cys[i]*ca;}

    /* Re-cluster in rotated frame */
    for(int i=0;i<nc;i++) si2[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(rys[si2[j]]<rys[si2[i]]){int t=si2[i];si2[i]=si2[j];si2[j]=t;}
    int nr2=1;rs[0]=0;rcnt[0]=1;
    for(int i=1;i<nc;i++){
        if(rys[si2[i]]-rys[si2[i-1]]>gap_th){nr2++;rs[nr2-1]=i;rcnt[nr2-1]=1;}
        else rcnt[nr2-1]++;}

    /* X spacings from consecutive dots within rows */
    int mxs=nc*4;
    double *xsps=(double*)malloc(mxs*sizeof(double));
    double *ysps=(double*)malloc(mxs*sizeof(double));
    if(!xsps||!ysps){free(cxs);free(cys);free(si2);free(rs);free(rcnt);
        free(rxs);free(rys);free(xsps);free(ysps);return;}
    int nxs=0,nys=0;
    for(int r=0;r<nr2;r++){
        if(rcnt[r]<2) continue;
        int rstart=rs[r],cnt=rcnt[r];
        double *row_x=(double*)malloc(cnt*sizeof(double));if(!row_x)continue;
        for(int k=0;k<cnt;k++) row_x[k]=rxs[si2[rstart+k]];
        for(int i=0;i<cnt-1;i++) for(int j=i+1;j<cnt;j++)
            if(row_x[j]<row_x[i]){double t=row_x[i];row_x[i]=row_x[j];row_x[j]=t;}
        for(int k=0;k<cnt-1;k++){double d=row_x[k+1]-row_x[k];
            if(d>med_nn*0.6&&d<med_nn*1.5&&nxs<mxs) xsps[nxs++]=d;}
        free(row_x);}

    /* Y spacings between row mean-Ys */
    double *rmy=(double*)malloc(nr2*sizeof(double));int nrmy=0;
    /* Also store per-row mean-X for staggered detection */
    double *rmx=(double*)malloc(nr2*sizeof(double));
    int *rmi=(int*)calloc(nr2,sizeof(int)); /* row index mapping */
    if(rmy&&rmx&&rmi){for(int r=0;r<nr2;r++){if(rcnt[r]<2){rmx[r]=0;continue;}
        double sx2=0,sy2=0;for(int k=0;k<rcnt[r];k++){
            sx2+=rxs[si2[rs[r]+k]];sy2+=rys[si2[rs[r]+k]];}
        rmx[nrmy]=sx2/rcnt[r];rmy[nrmy]=sy2/rcnt[r];rmi[nrmy]=r;nrmy++;}
    for(int i=0;i<nrmy-1;i++) for(int j=i+1;j<nrmy;j++)
        if(rmy[j]<rmy[i]){double t=rmy[i];rmy[i]=rmy[j];rmy[j]=t;
            t=rmx[i];rmx[i]=rmx[j];rmx[j]=t;
            int ti=rmi[i];rmi[i]=rmi[j];rmi[j]=ti;}
    for(int i=0;i<nrmy-1;i++){double d=rmy[i+1]-rmy[i];
        if(d>med_nn*0.6&&d<med_nn*1.5&&nys<mxs) ysps[nys++]=d;}
    }

    if(nxs<2||nys<2){free(cxs);free(cys);free(si2);free(rs);free(rcnt);
        free(rxs);free(rys);free(xsps);free(ysps);free(rmy);free(rmx);free(rmi);return;}
    gp->spacing_x=median_arr(xsps,nxs);gp->spacing_y=median_arr(ysps,nys);

    /* Staggered detection: check if alternate rows have X-offset of ~half spacing */
    if(gridpat==GRIDPAT_STAGGERED && nrmy>=3 && gp->spacing_x>1.0){
        /* Compute the first-dot X offset (mod spacing_x) for each row */
        int stag_votes=0,nstag=0;
        for(int i=0;i<nrmy;i++){
            /* Find min X in this row */
            int r=rmi[i]; int rstart=rs[r],cnt=rcnt[r];
            double min_rx=1e18;
            for(int k=0;k<cnt;k++){double x=rxs[si2[rstart+k]];if(x<min_rx)min_rx=x;}
            /* Compute phase of this row relative to first row */
            double phase=fmod(min_rx, gp->spacing_x);
            if(phase<0) phase+=gp->spacing_x;
            /* Check if odd rows are shifted by ~half spacing relative to even rows */
            if(i>0){
                int r0=rmi[0]; int rs0=rs[r0],cnt0=rcnt[r0];
                double min_rx0=1e18;
                for(int k=0;k<cnt0;k++){double x=rxs[si2[rs0+k]];if(x<min_rx0)min_rx0=x;}
                double delta=fmod(fabs(min_rx-min_rx0), gp->spacing_x);
                if(delta>gp->spacing_x/2) delta=gp->spacing_x-delta;
                nstag++;
                /* Half-spacing offset within 25% tolerance */
                if(fabs(delta-gp->spacing_x/2.0)<gp->spacing_x*0.25) stag_votes++;
            }
        }
        if(nstag>0 && stag_votes*2>=nstag) gp->staggered=1;
    }
    /* Also force staggered if user selected it and we have enough rows */
    if(gridpat==GRIDPAT_STAGGERED) gp->staggered=1;

    /* Grid origin via iterative least-squares */
    double sx=gp->spacing_x,sy=gp->spacing_y,ox=rxs[0],oy=rys[0];
    for(int iter=0;iter<5;iter++){double srx=0,sry=0;
        for(int i=0;i<nc;i++){
            int row=(int)round((rys[i]-oy)/sy);
            double row_ox=ox;
            if(gp->staggered && (row&1)) row_ox=ox+sx/2.0;
            int col=(int)round((rxs[i]-row_ox)/sx);
            srx+=rxs[i]-col*sx-(gp->staggered&&(row&1)?sx/2.0:0.0);
            sry+=rys[i]-row*sy;}
        ox=srx/nc;oy=sry/nc;}
    gp->origin_x=ox;gp->origin_y=oy;gp->valid=1;

    free(xsps);free(ysps);free(rs);free(rcnt);free(rxs);free(rys);free(si2);
    free(cxs);free(cys);free(rmy);free(rmx);free(rmi);
}

/* ===== CHECKER / STAGGERED GRID INFERENCE (column-first) ===== */

static void infer_grid_params_checker(const blob_t *blobs,int nblobs,grid_params_t *gp){
    gp->valid=0;gp->staggered=0;gp->stagger_y=0;
    /* Collect non-merged centroids */
    int nc=0;
    double *cxs=(double*)malloc(nblobs*sizeof(double));
    double *cys=(double*)malloc(nblobs*sizeof(double));
    if(!cxs||!cys){free(cxs);free(cys);return;}
    for(int i=0;i<nblobs;i++)if(!blobs[i].merged){cxs[nc]=blobs[i].cx;cys[nc]=blobs[i].cy;nc++;}
    if(nc<4){free(cxs);free(cys);return;}

    /* Nearest-neighbor median for spacing estimate */
    double *nn_d=(double*)malloc(nc*sizeof(double));
    if(!nn_d){free(cxs);free(cys);return;}
    for(int i=0;i<nc;i++){double best=1e18;for(int j=0;j<nc;j++){if(i==j)continue;
        double d=(cxs[i]-cxs[j])*(cxs[i]-cxs[j])+(cys[i]-cys[j])*(cys[i]-cys[j]);
        if(d<best)best=d;}nn_d[i]=sqrt(best);}
    double med_nn=median_arr(nn_d,nc);free(nn_d);

    /* Sort indices by X for column clustering */
    int *si_x=(int*)malloc(nc*sizeof(int));if(!si_x){free(cxs);free(cys);return;}
    for(int i=0;i<nc;i++) si_x[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(cxs[si_x[j]]<cxs[si_x[i]]){int t=si_x[i];si_x[i]=si_x[j];si_x[j]=t;}

    /* Cluster into columns (X-gap > spacing*0.4) */
    double col_gap_th=med_nn*0.4;
    int max_cols=nc;
    int *col_start=(int*)calloc(max_cols,sizeof(int));
    int *col_count=(int*)calloc(max_cols,sizeof(int));
    if(!col_start||!col_count){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);return;}
    int ncols=1;col_start[0]=0;col_count[0]=1;
    for(int i=1;i<nc;i++){
        if(cxs[si_x[i]]-cxs[si_x[i-1]]>col_gap_th){ncols++;col_start[ncols-1]=i;col_count[ncols-1]=1;}
        else col_count[ncols-1]++;}

    /* --- Compute grid angle from rows detected via Y clustering within columns --- */
    /* First pass: estimate row slopes by fitting lines across columns at same row height */
    /* For now, use the same row-based slope detection as the rectangular version */
    /* Sort all centroids by Y, cluster into rows */
    int *si_y=(int*)malloc(nc*sizeof(int));
    if(!si_y){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);return;}
    for(int i=0;i<nc;i++) si_y[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(cys[si_y[j]]<cys[si_y[i]]){int t=si_y[i];si_y[i]=si_y[j];si_y[j]=t;}
    double row_gap_th=med_nn*0.35; /* tighter threshold to separate interleaved rows */
    int *row_start=(int*)calloc(nc,sizeof(int)),*row_count=(int*)calloc(nc,sizeof(int));
    if(!row_start||!row_count){free(cxs);free(cys);free(si_x);free(si_y);
        free(col_start);free(col_count);free(row_start);free(row_count);return;}
    int nrows=1;row_start[0]=0;row_count[0]=1;
    for(int i=1;i<nc;i++){
        if(cys[si_y[i]]-cys[si_y[i-1]]>row_gap_th){nrows++;row_start[nrows-1]=i;row_count[nrows-1]=1;}
        else row_count[nrows-1]++;}

    /* Fit line to each row with >=3 dots to get slope */
    double *slopes=(double*)malloc(nrows*sizeof(double));
    int nslopes=0;
    if(slopes){
        for(int r=0;r<nrows;r++){
            if(row_count[r]<3) continue;
            int rs2=row_start[r],cnt=row_count[r];
            double xmin=1e18,xmax=-1e18;
            for(int k=0;k<cnt;k++){int idx=si_y[rs2+k];
                if(cxs[idx]<xmin)xmin=cxs[idx];if(cxs[idx]>xmax)xmax=cxs[idx];}
            if(xmax-xmin<med_nn*1.5) continue;
            double Sx=0,Sy=0,Sxy=0,Sxx=0;
            for(int k=0;k<cnt;k++){int idx=si_y[rs2+k];
                Sx+=cxs[idx];Sy+=cys[idx];Sxy+=cxs[idx]*cys[idx];Sxx+=cxs[idx]*cxs[idx];}
            double denom=cnt*Sxx-Sx*Sx;
            if(fabs(denom)<1e-12) continue;
            slopes[nslopes++]=(cnt*Sxy-Sx*Sy)/denom;
        }
    }
    double angle=0;
    if(nslopes>=1) angle=atan(median_arr(slopes,nslopes));
    free(slopes);free(row_start);free(row_count);free(si_y);
    gp->angle=angle;

    /* Rotate all points to grid-aligned frame */
    double ca=cos(-angle),sna=sin(-angle);
    double *rxs=(double*)malloc(nc*sizeof(double)),*rys=(double*)malloc(nc*sizeof(double));
    if(!rxs||!rys){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);free(rxs);free(rys);return;}
    for(int i=0;i<nc;i++){rxs[i]=cxs[i]*ca-cys[i]*sna;rys[i]=cxs[i]*sna+cys[i]*ca;}

    /* Re-cluster into columns in rotated frame */
    for(int i=0;i<nc;i++) si_x[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(rxs[si_x[j]]<rxs[si_x[i]]){int t=si_x[i];si_x[i]=si_x[j];si_x[j]=t;}
    ncols=1;col_start[0]=0;col_count[0]=1;
    for(int i=1;i<nc;i++){
        if(rxs[si_x[i]]-rxs[si_x[i-1]]>col_gap_th){ncols++;col_start[ncols-1]=i;col_count[ncols-1]=1;}
        else col_count[ncols-1]++;}

    /* Compute column mean-X positions and collect dx spacings */
    double *col_mx=(double*)malloc(ncols*sizeof(double));
    if(!col_mx){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);free(rxs);free(rys);return;}
    for(int c=0;c<ncols;c++){
        double sx2=0;
        for(int k=0;k<col_count[c];k++) sx2+=rxs[si_x[col_start[c]+k]];
        col_mx[c]=sx2/col_count[c];
    }
    int max_sp=ncols*4;
    double *dxs=(double*)malloc(max_sp*sizeof(double));
    double *dys=(double*)malloc(max_sp*sizeof(double));
    if(!dxs||!dys){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);
        free(rxs);free(rys);free(col_mx);free(dxs);free(dys);return;}
    int ndx=0,ndy=0;
    /* dx from consecutive column means */
    for(int c=0;c<ncols-1;c++){
        double d=col_mx[c+1]-col_mx[c];
        if(d>med_nn*0.6&&d<med_nn*1.5&&ndx<max_sp) dxs[ndx++]=d;
    }
    /* dy from within-column consecutive Y spacings */
    for(int c=0;c<ncols;c++){
        if(col_count[c]<2) continue;
        int cs=col_start[c],cnt=col_count[c];
        /* Sort this column's dots by Y */
        double *cy_arr=(double*)malloc(cnt*sizeof(double));if(!cy_arr)continue;
        for(int k=0;k<cnt;k++) cy_arr[k]=rys[si_x[cs+k]];
        qsort(cy_arr,cnt,sizeof(double),cmp_double);
        for(int k=0;k<cnt-1;k++){double d=cy_arr[k+1]-cy_arr[k];
            if(d>med_nn*0.6&&d<med_nn*1.8&&ndy<max_sp) dys[ndy++]=d;}
        free(cy_arr);
    }
    if(ndx<1||ndy<1){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);
        free(rxs);free(rys);free(col_mx);free(dxs);free(dys);return;}
    gp->spacing_x=median_arr(dxs,ndx);
    gp->spacing_y=median_arr(dys,ndy);
    free(dxs);free(dys);

    /* Compute stagger: Y offset of odd-indexed columns vs even-indexed columns.
       For each column, compute the fractional phase = fmod(first_Y, spacing_y).
       Compare even-column phases to odd-column phases. */
    double *even_phases=(double*)malloc(ncols*sizeof(double));
    double *odd_phases=(double*)malloc(ncols*sizeof(double));
    int neven=0,nodd=0;
    if(even_phases&&odd_phases){
        for(int c=0;c<ncols;c++){
            if(col_count[c]<2) continue;
            /* Find this column's Y positions, compute median residual mod dy */
            int cs=col_start[c],cnt=col_count[c];
            double *resid=(double*)malloc(cnt*sizeof(double));
            if(!resid)continue;
            for(int k=0;k<cnt;k++){
                double y=rys[si_x[cs+k]];
                double r=fmod(y,gp->spacing_y);if(r<0)r+=gp->spacing_y;
                resid[k]=r;
            }
            /* Use circular mean to handle wrap-around near spacing_y boundary */
            double sin_sum=0,cos_sum=0;
            for(int k=0;k<cnt;k++){
                double ang=2.0*PI*resid[k]/gp->spacing_y;
                sin_sum+=sin(ang);cos_sum+=cos(ang);
            }
            double phase=atan2(sin_sum,cos_sum)*gp->spacing_y/(2.0*PI);
            if(phase<0)phase+=gp->spacing_y;
            free(resid);
            if(c%2==0) even_phases[neven++]=phase;
            else odd_phases[nodd++]=phase;
        }
    }
    double stagger_y=0;
    if(neven>=1&&nodd>=1){
        double ep=median_arr(even_phases,neven);
        double op=median_arr(odd_phases,nodd);
        stagger_y=op-ep;
        /* Normalize to [-spacing_y/2, spacing_y/2] */
        if(stagger_y>gp->spacing_y/2.0) stagger_y-=gp->spacing_y;
        if(stagger_y<-gp->spacing_y/2.0) stagger_y+=gp->spacing_y;
        /* Only flag as staggered if offset is significant (>10% of dy) */
        if(fabs(stagger_y)>gp->spacing_y*0.10){
            gp->staggered=1;
            gp->stagger_y=stagger_y;
        }
    }
    free(even_phases);free(odd_phases);

    /* Grid origin via iterative least-squares */
    double sx=gp->spacing_x,sy=gp->spacing_y,ox=rxs[0],oy=rys[0];
    for(int iter=0;iter<8;iter++){
        double srx=0,sry=0;
        for(int i=0;i<nc;i++){
            int col=(int)round((rxs[i]-ox)/sx);
            double col_oy=oy;
            if(gp->staggered&&(col&1)) col_oy=oy+gp->stagger_y;
            int row=(int)round((rys[i]-col_oy)/sy);
            srx+=rxs[i]-col*sx;
            sry+=rys[i]-row*sy-(gp->staggered&&(col&1)?gp->stagger_y:0.0);
        }
        ox=srx/nc;oy=sry/nc;
    }
    gp->origin_x=ox;gp->origin_y=oy;gp->valid=1;

    free(col_mx);free(col_start);free(col_count);free(si_x);
    free(rxs);free(rys);free(cxs);free(cys);
}

static void compute_grid_offsets(blob_t *blobs,int nblobs,const grid_params_t *gp,double px_mm,int use_body){
    if(!gp->valid)return;
    double ca=cos(-gp->angle),sa=sin(-gp->angle),sx=gp->spacing_x,sy=gp->spacing_y;
    if(sx<1||sy<1)return;
    double ox=gp->origin_x,oy=gp->origin_y;
    double rca=cos(gp->angle),rsa=sin(gp->angle);
    int use_stagger_y=(gp->staggered && fabs(gp->stagger_y)>0.01);
    for(int i=0;i<nblobs;i++){
        if(blobs[i].merged)continue;
        double pcx=use_body?blobs[i].body_cx:(double)blobs[i].cx;
        double pcy=use_body?blobs[i].body_cy:(double)blobs[i].cy;
        double rx=pcx*ca-pcy*sa,ry=pcx*sa+pcy*ca;
        double erx,ery;
        if(use_stagger_y){
            /* Checker pattern: odd columns are shifted in Y by stagger_y */
            int col=(int)round((rx-ox)/sx);
            double col_oy=oy;
            if(col&1) col_oy=oy+gp->stagger_y;
            int row=(int)round((ry-col_oy)/sy);
            erx=rx-(ox+col*sx);
            ery=ry-(col_oy+row*sy);
            blobs[i].grid_col=col;blobs[i].grid_row=row;
        }else if(gp->staggered){
            /* Legacy hex stagger: odd rows shifted in X by sx/2 */
            int row=(int)round((ry-oy)/sy);
            double row_ox=ox;
            if(row&1) row_ox=ox+sx/2.0;
            int col=(int)round((rx-row_ox)/sx);
            erx=rx-(row_ox+col*sx);ery=ry-(oy+row*sy);
            blobs[i].grid_col=col;blobs[i].grid_row=row;
        }else{
            int row=(int)round((ry-oy)/sy);
            int col=(int)round((rx-ox)/sx);
            erx=rx-(ox+col*sx);ery=ry-(oy+row*sy);
            blobs[i].grid_col=col;blobs[i].grid_row=row;
        }
        double ex=erx*rca-ery*rsa,ey=erx*rsa+ery*rca;
        blobs[i].offset_x_mm=ex/px_mm;blobs[i].offset_y_mm=ey/px_mm;
        blobs[i].offset_total_px=sqrt(erx*erx+ery*ery);
        blobs[i].grid_valid=1;
    }
}

/* Count missed dots: grid positions within image bounds where no dot was detected.
   Returns the count of missing positions. */
static int count_missed_dots(const blob_t *blobs,int nblobs,const grid_params_t *gp,
    int img_w,int img_h){
    if(!gp->valid||nblobs<2) return 0;
    double sx=gp->spacing_x,sy=gp->spacing_y;
    double ox=gp->origin_x,oy=gp->origin_y;
    double rca=cos(gp->angle),rsa=sin(gp->angle);
    double ca=cos(-gp->angle),sa=sin(-gp->angle);

    /* Find the range of grid rows/cols actually occupied by detected dots */
    int min_row=999999,max_row=-999999,min_col=999999,max_col=-999999;
    for(int i=0;i<nblobs;i++){
        if(blobs[i].merged||!blobs[i].grid_valid) continue;
        if(blobs[i].grid_row<min_row) min_row=blobs[i].grid_row;
        if(blobs[i].grid_row>max_row) max_row=blobs[i].grid_row;
        if(blobs[i].grid_col<min_col) min_col=blobs[i].grid_col;
        if(blobs[i].grid_col>max_col) max_col=blobs[i].grid_col;
    }
    if(min_row>max_row) return 0;

    /* Build a set of occupied (row,col) positions */
    int nrows=max_row-min_row+1, ncols=max_col-min_col+1;
    if(nrows<=0||ncols<=0||nrows>500||ncols>500) return 0;
    uint8_t *occupied=(uint8_t*)calloc(nrows*ncols,1);
    if(!occupied) return 0;
    for(int i=0;i<nblobs;i++){
        if(blobs[i].merged||!blobs[i].grid_valid) continue;
        int r=blobs[i].grid_row-min_row, c=blobs[i].grid_col-min_col;
        if(r>=0&&r<nrows&&c>=0&&c<ncols) occupied[r*ncols+c]=1;
    }

    /* Count grid positions that are within image bounds but have no dot */
    int missed=0;
    double margin=sx*0.3; /* allow some margin from image edges */
    int use_stagger_y=(gp->staggered && fabs(gp->stagger_y)>0.01);
    for(int r=0;r<nrows;r++){
        int row=r+min_row;
        for(int c=0;c<ncols;c++){
            int col=c+min_col;
            if(occupied[r*ncols+c]) continue;
            /* Compute image-space position of this grid node */
            double rx,ry;
            if(use_stagger_y){
                rx=ox+col*sx;
                double col_oy=oy;
                if(col&1) col_oy=oy+gp->stagger_y;
                ry=col_oy+row*sy;
            }else{
                double row_ox=ox;
                if(gp->staggered && (row&1)) row_ox=ox+sx/2.0;
                rx=row_ox+col*sx; ry=oy+row*sy;
            }
            double ix=rx*rca-ry*rsa, iy=rx*rsa+ry*rca;
            /* Check if within image bounds (with margin) */
            if(ix>=margin && ix<img_w-margin && iy>=margin && iy<img_h-margin)
                missed++;
        }
    }
    free(occupied);
    return missed;
}

/* ===== ANNOTATION (PGM file output) ===== */
static void dpx(pgm_image_t *img,int x,int y,uint8_t v){
    if(x>=0&&x<img->width&&y>=0&&y<img->height)img->pixels[y*img->width+x]=v;}
static void drect(pgm_image_t *img,int x1,int y1,int x2,int y2,uint8_t v){
    for(int x=x1;x<=x2;x++){dpx(img,x,y1,v);dpx(img,x,y2,v);}
    for(int y=y1;y<=y2;y++){dpx(img,x1,y,v);dpx(img,x2,y,v);}}
static void dchar(pgm_image_t *img,int ox,int oy,char c,uint8_t v){
    int fi=font_index(c);if(fi<0||fi>=19)return;
    for(int r=0;r<FONT_H;r++){uint8_t bits=font_5x7[fi][r];
    for(int col=0;col<FONT_W;col++)if(bits&(0x10>>col))dpx(img,ox+col,oy+r,v);}}
static void dstr(pgm_image_t *img,int x,int y,const char *s,uint8_t v){
    while(*s){dchar(img,x,y,*s,v);x+=FONT_W+1;s++;}}
static uint8_t tcol(const pgm_image_t *img,int x1,int y1,int x2,int y2){
    long s=0;int c=0;
    for(int y=(y1<0?0:y1);y<=y2&&y<img->height;y++)
        for(int x=(x1<0?0:x1);x<=x2&&x<img->width;x++){s+=img->pixels[y*img->width+x];c++;}
    return(c==0||s/c>128)?0:255;}

/* ===== FILE ENUMERATION ===== */
static int find_pgm_files(const char *folder,char files[][MAX_PATH_LEN],int mx){
    char pat[MAX_PATH_LEN];snprintf(pat,MAX_PATH_LEN,"%s\\*.pgm",folder);
    WIN32_FIND_DATAA fd;HANDLE hF=FindFirstFileA(pat,&fd);
    if(hF==INVALID_HANDLE_VALUE)return 0;int n=0;
    do{if(!(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)){
        snprintf(files[n],MAX_PATH_LEN,"%s\\%s",folder,fd.cFileName);n++;
    }}while(FindNextFileA(hF,&fd)&&n<mx);FindClose(hF);
    for(int i=0;i<n-1;i++)for(int j=i+1;j<n;j++)
        if(strcmp(files[i],files[j])>0){char t[MAX_PATH_LEN];strcpy(t,files[i]);strcpy(files[i],files[j]);strcpy(files[j],t);}
    return n;
}

/* ===== STATISTICS ===== */
static void si(stats_t *s,int c){s->sum=s->sum_sq=0;s->min_val=1e30;s->max_val=-1e30;
    s->count=0;s->values=NULL;s->values_cap=0;
    if(c>0){s->values=(double*)malloc(c*sizeof(double));s->values_cap=c;}}
static void sa(stats_t *s,double v){s->sum+=v;s->sum_sq+=v*v;
    if(v<s->min_val)s->min_val=v;if(v>s->max_val)s->max_val=v;
    if(s->values&&s->count<s->values_cap)s->values[s->count]=v;s->count++;}
static double smean(const stats_t *s){return s->count>0?s->sum/s->count:0;}
static double sstd(const stats_t *s){if(s->count<2)return 0;
    double m=s->sum/s->count,v=s->sum_sq/s->count-m*m;return v>0?sqrt(v):0;}
static double smed(stats_t *s){if(s->count==0||!s->values)return 0;
    int n=s->count<s->values_cap?s->count:s->values_cap;
    qsort(s->values,n,sizeof(double),cmp_double);
    return n%2==1?s->values[n/2]:(s->values[n/2-1]+s->values[n/2])/2.0;}
static void sfree(stats_t *s){if(s->values){free(s->values);s->values=NULL;}}

/* ===== RGB DRAWING HELPERS (for preview buffer) ===== */
static void rgb_px(uint8_t *rgb,int w,int h,int x,int y,uint8_t r,uint8_t g,uint8_t b){
    if(x>=0&&x<w&&y>=0&&y<h){int i=(y*w+x)*3;rgb[i]=b;rgb[i+1]=g;rgb[i+2]=r;}}

/* Draw "+" crosshair, color interpolated green→red by factor f (0=green,1=red) */
static void rgb_cross(uint8_t *rgb,int w,int h,int cx,int cy,double f,int sz){
    if(f<0)f=0;if(f>1)f=1;
    uint8_t r=(uint8_t)(255*f),g=(uint8_t)(255*(1-f)),b=0;
    for(int d=-sz;d<=sz;d++){rgb_px(rgb,w,h,cx+d,cy,r,g,b);rgb_px(rgb,w,h,cx,cy+d,r,g,b);}
}

/* Draw dashed line using Bresenham's */
static void rgb_dash(uint8_t *rgb,int w,int h,int x0,int y0,int x1,int y1,
    uint8_t r,uint8_t g,uint8_t b,int dash_on,int dash_off){
    int dx2=abs(x1-x0),dy2=abs(y1-y0);
    int sx2=x0<x1?1:-1,sy2=y0<y1?1:-1;
    int err=dx2-dy2,step=0,total=dash_on+dash_off;
    for(;;){
        if(step%total<dash_on) rgb_px(rgb,w,h,x0,y0,r,g,b);
        if(x0==x1&&y0==y1)break;
        int e2=2*err;if(e2>-dy2){err-=dy2;x0+=sx2;}if(e2<dx2){err+=dx2;y0+=sy2;}step++;
    }
}

/* ===== PREVIEW ===== */
static int get_mode(void){return(int)SendMessageW(g_combo_mode,CB_GETCURSEL,0,0);}
static int get_gridpat(void){return(int)SendMessageW(g_combo_gridpat,CB_GETCURSEL,0,0);}
static int get_thresh(void){
    int at=(SendMessageW(g_check_auto,BM_GETCHECK,0,0)==BST_CHECKED);
    if(at&&g_preview_img.pixels)
        return compute_otsu(g_preview_img.pixels,g_preview_img.width*g_preview_img.height);
    return(int)SendMessageW(g_slider_thresh,TBM_GETPOS,0,0);
}
static int get_minarea(void){return(int)SendMessageW(g_slider_minarea,TBM_GETPOS,0,0);}
static int get_erosion(void){return(int)SendMessageW(g_slider_erosion,TBM_GETPOS,0,0);}

static void build_preview_rgb(void){
    if(!g_preview_img.pixels||!g_preview_rgb) return;
    /* Hide any active tooltip since blob data is about to change */
    if(g_tooltip&&g_hover_blob_idx>=0){
        g_hover_blob_idx=-1;
        TOOLINFOW ti;memset(&ti,0,sizeof(ti));
        ti.cbSize=sizeof(ti);ti.hwnd=g_preview_panel;ti.uId=0;
        SendMessageW(g_tooltip,TTM_TRACKACTIVATE,FALSE,(LPARAM)&ti);
    }
    int w=g_preview_img.width,h=g_preview_img.height;
    int thresh=get_thresh(),min_area=get_minarea(),erosion_r=get_erosion();
    int mode=get_mode();if(mode<0)mode=MODE_BBOX;
    int show_cross=(SendMessageW(g_check_cross,BM_GETCHECK,0,0)==BST_CHECKED);
    int show_grid=(SendMessageW(g_check_grid,BM_GETCHECK,0,0)==BST_CHECKED);
    int need_full=(mode==MODE_BODY||show_cross||show_grid);

    if(SendMessageW(g_check_auto,BM_GETCHECK,0,0)==BST_CHECKED){
        g_updating=1;
        SendMessageW(g_slider_thresh,TBM_SETPOS,TRUE,thresh);
        wchar_t tb[32];swprintf(tb,32,L"%d",thresh);SetWindowTextW(g_edit_thresh,tb);
        g_updating=0;
    }

    /* Gray→BGR */
    for(int i=0;i<w*h;i++){uint8_t v=g_preview_img.pixels[i];
        g_preview_rgb[i*3]=v;g_preview_rgb[i*3+1]=v;g_preview_rgb[i*3+2]=v;}

    /* Run analysis */
    if(need_full)
        g_preview_nblobs=process_image_full(&g_preview_img,thresh,min_area,erosion_r,
            g_preview_blobs,MAX_BLOBS);
    else
        g_preview_nblobs=process_image_light(&g_preview_img,thresh,min_area,
            g_preview_blobs,MAX_BLOBS);

    /* Grid inference if needed */
    g_preview_gp.valid=0;
    int gridpat=get_gridpat();
    int missed_dots=0;
    if(show_cross||show_grid){
        if(gridpat==GRIDPAT_STAGGERED)
            infer_grid_params_checker(g_preview_blobs,g_preview_nblobs,&g_preview_gp);
        else
            infer_grid_params(g_preview_blobs,g_preview_nblobs,&g_preview_gp,gridpat);
        if(g_preview_gp.valid){
            compute_grid_offsets(g_preview_blobs,g_preview_nblobs,&g_preview_gp,10.0,mode==MODE_BODY);
            missed_dots=count_missed_dots(g_preview_blobs,g_preview_nblobs,&g_preview_gp,w,h);
        }
    }

    /* Compute minimum detected blob area for display */
    g_preview_min_area_detected=0;
    if(g_preview_nblobs>0){
        int mn=0x7FFFFFFF;
        for(int i=0;i<g_preview_nblobs;i++)
            if(g_preview_blobs[i].area<mn) mn=g_preview_blobs[i].area;
        g_preview_min_area_detected=mn;
    }

    /* Draw grid lines */
    if(show_grid&&g_preview_gp.valid){
        double a=g_preview_gp.angle,sx=g_preview_gp.spacing_x,sy=g_preview_gp.spacing_y;
        double ox=g_preview_gp.origin_x,oy=g_preview_gp.origin_y;
        double ca2=cos(-a),sa2=sin(-a);
        int use_stagger_y=(g_preview_gp.staggered && fabs(g_preview_gp.stagger_y)>0.01);
        /* Compute rotated-frame bounds of image corners */
        double corners[4][2]={{0,0},{(double)(w-1),0},{0,(double)(h-1)},{(double)(w-1),(double)(h-1)}};
        double rmin_x=1e18,rmax_x=-1e18,rmin_y=1e18,rmax_y=-1e18;
        for(int c=0;c<4;c++){double rx=corners[c][0]*ca2-corners[c][1]*sa2;
            double ry=corners[c][0]*sa2+corners[c][1]*ca2;
            if(rx<rmin_x)rmin_x=rx;if(rx>rmax_x)rmax_x=rx;
            if(ry<rmin_y)rmin_y=ry;if(ry>rmax_y)rmax_y=ry;}
        int min_col=(int)floor((rmin_x-ox)/sx)-1,max_col=(int)ceil((rmax_x-ox)/sx)+1;
        int min_row=(int)floor((rmin_y-oy)/sy)-1,max_row=(int)ceil((rmax_y-oy)/sy)+1;
        double rca=cos(a),rsa=sin(a);

        if(use_stagger_y){
            /* Checker pattern: columns are straight verticals, rows shift per column */
            /* Draw column lines (straight vertical) */
            for(int col=min_col;col<=max_col;col++){
                double rx2=ox+col*sx;
                double ry0=rmin_y-sy,ry1=rmax_y+sy;
                int ix0=(int)(rx2*rca-ry0*rsa),iy0=(int)(rx2*rsa+ry0*rca);
                int ix1=(int)(rx2*rca-ry1*rsa),iy1=(int)(rx2*rsa+ry1*rca);
                rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,6,4);
            }
            /* Draw row lines per-column (short ticks showing expected Y positions) */
            double tick_half=sx*0.45; /* horizontal extent of each tick */
            for(int col=min_col;col<=max_col;col++){
                double col_oy=oy;
                if(col&1) col_oy=oy+g_preview_gp.stagger_y;
                double rx_c=ox+col*sx;
                for(int row=min_row;row<=max_row;row++){
                    double ry2=col_oy+row*sy;
                    double rx0=rx_c-tick_half,rx1=rx_c+tick_half;
                    int ix0=(int)(rx0*rca-ry2*rsa),iy0=(int)(rx0*rsa+ry2*rca);
                    int ix1=(int)(rx1*rca-ry2*rsa),iy1=(int)(rx1*rsa+ry2*rca);
                    rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,4,4);
                }
            }
        }else{
            /* Row lines (horizontal in rotated frame) */
            for(int row=min_row;row<=max_row;row++){
                double ry=oy+row*sy;
                double rx0=rmin_x-sx,rx1=rmax_x+sx;
                int ix0=(int)(rx0*rca-ry*rsa),iy0=(int)(rx0*rsa+ry*rca);
                int ix1=(int)(rx1*rca-ry*rsa),iy1=(int)(rx1*rsa+ry*rca);
                rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,6,4);
            }
            /* Column lines */
            if(g_preview_gp.staggered){
                /* Legacy hex stagger: column lines per-row */
                for(int row=min_row;row<=max_row;row++){
                    double ry=oy+row*sy;
                    double row_ox=ox;
                    if(row&1) row_ox=ox+sx/2.0;
                    for(int col=min_col;col<=max_col;col++){
                        double rx2=row_ox+col*sx;
                        double ry0=ry-sy*0.5,ry1=ry+sy*0.5;
                        int ix0=(int)(rx2*rca-ry0*rsa),iy0=(int)(rx2*rsa+ry0*rca);
                        int ix1=(int)(rx2*rca-ry1*rsa),iy1=(int)(rx2*rsa+ry1*rca);
                        rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,4,4);
                    }
                }
            }else{
                for(int col=min_col;col<=max_col;col++){
                    double rx2=ox+col*sx;
                    double ry0=rmin_y-sy,ry1=rmax_y+sy;
                    int ix0=(int)(rx2*rca-ry0*rsa),iy0=(int)(rx2*rsa+ry0*rca);
                    int ix1=(int)(rx2*rca-ry1*rsa),iy1=(int)(rx2*rsa+ry1*rca);
                    rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,6,4);
                }
            }
        }

        /* Draw missed dot markers (red circles) at empty grid positions */
        if(missed_dots>0&&g_preview_nblobs>1){
            /* Find occupied positions */
            int gmin_r=999999,gmax_r=-999999,gmin_c=999999,gmax_c=-999999;
            for(int bi=0;bi<g_preview_nblobs;bi++){
                blob_t *b2=&g_preview_blobs[bi];
                if(b2->merged||!b2->grid_valid)continue;
                if(b2->grid_row<gmin_r)gmin_r=b2->grid_row;if(b2->grid_row>gmax_r)gmax_r=b2->grid_row;
                if(b2->grid_col<gmin_c)gmin_c=b2->grid_col;if(b2->grid_col>gmax_c)gmax_c=b2->grid_col;
            }
            int gnr=gmax_r-gmin_r+1,gnc=gmax_c-gmin_c+1;
            if(gnr>0&&gnc>0&&gnr<=500&&gnc<=500){
                uint8_t *occ=(uint8_t*)calloc(gnr*gnc,1);
                if(occ){
                    for(int bi=0;bi<g_preview_nblobs;bi++){
                        blob_t *b2=&g_preview_blobs[bi];
                        if(b2->merged||!b2->grid_valid)continue;
                        int rr=b2->grid_row-gmin_r,cc=b2->grid_col-gmin_c;
                        if(rr>=0&&rr<gnr&&cc>=0&&cc<gnc)occ[rr*gnc+cc]=1;
                    }
                    double margin=sx*0.3;
                    int use_stagger_y2=(g_preview_gp.staggered && fabs(g_preview_gp.stagger_y)>0.01);
                    for(int rr=0;rr<gnr;rr++)for(int cc=0;cc<gnc;cc++){
                        if(occ[rr*gnc+cc])continue;
                        int row=rr+gmin_r,col=cc+gmin_c;
                        double rrx,rry;
                        if(use_stagger_y2){
                            rrx=ox+col*sx;
                            double col_oy=oy;
                            if(col&1) col_oy=oy+g_preview_gp.stagger_y;
                            rry=col_oy+row*sy;
                        }else{
                            double row_ox2=ox;
                            if(g_preview_gp.staggered&&(row&1))row_ox2=ox+sx/2.0;
                            rrx=row_ox2+col*sx;rry=oy+row*sy;
                        }
                        double ix2=rrx*rca-rry*rsa,iy2=rrx*rsa+rry*rca;
                        if(ix2>=margin&&ix2<w-margin&&iy2>=margin&&iy2<h-margin){
                            /* Draw a red circle marker */
                            int cix=(int)ix2,ciy=(int)iy2,rad=6;
                            for(int da=0;da<360;da+=5){
                                double ar=da*PI/180.0;
                                int px=(int)(cix+rad*cos(ar)),py=(int)(ciy+rad*sin(ar));
                                rgb_px(g_preview_rgb,w,h,px,py,255,0,0);
                            }
                            /* Also draw an X */
                            for(int dd=-4;dd<=4;dd++){
                                rgb_px(g_preview_rgb,w,h,cix+dd,ciy+dd,255,0,0);
                                rgb_px(g_preview_rgb,w,h,cix+dd,ciy-dd,255,0,0);
                            }
                        }
                    }
                    free(occ);
                }
            }
        }
    }

    /* Draw bounding boxes */
    for(int bi=0;bi<g_preview_nblobs;bi++){
        blob_t *b=&g_preview_blobs[bi];
        int bx0,by0,bx1,by1;
        if(mode==MODE_BODY&&need_full){
            bx0=b->body_min_x-BORDER_PAD;by0=b->body_min_y-BORDER_PAD;
            bx1=b->body_max_x+BORDER_PAD;by1=b->body_max_y+BORDER_PAD;
        }else{
            bx0=b->min_x-BORDER_PAD;by0=b->min_y-BORDER_PAD;
            bx1=b->max_x+BORDER_PAD;by1=b->max_y+BORDER_PAD;
        }
        if(bx0<0)bx0=0;if(by0<0)by0=0;if(bx1>=w)bx1=w-1;if(by1>=h)by1=h-1;
        uint8_t cr=b->merged?255:0,cg=b->merged?0:255,cb=0;
        for(int x=bx0;x<=bx1;x++)for(int t=0;t<2;t++){
            int yy=(t==0)?by0+t:by1-t+1;if(yy>=0&&yy<h)rgb_px(g_preview_rgb,w,h,x,yy,cr,cg,cb);}
        for(int y=by0;y<=by1;y++)for(int t=0;t<2;t++){
            int xx=(t==0)?bx0+t:bx1-t+1;if(xx>=0&&xx<w)rgb_px(g_preview_rgb,w,h,xx,y,cr,cg,cb);}
    }

    /* Draw crosshairs */
    if(show_cross){
        double max_off=g_preview_gp.valid?(g_preview_gp.spacing_x*0.25):20.0;
        if(max_off<5)max_off=5;
        for(int bi=0;bi<g_preview_nblobs;bi++){
            blob_t *b=&g_preview_blobs[bi];if(b->merged)continue;
            int ccx=(int)(mode==MODE_BODY?b->body_cx:(double)b->cx);
            int ccy=(int)(mode==MODE_BODY?b->body_cy:(double)b->cy);
            double f=b->grid_valid?b->offset_total_px/max_off:0;
            rgb_cross(g_preview_rgb,w,h,ccx,ccy,f,5);
        }
    }

    int mg=0;for(int i=0;i<g_preview_nblobs;i++)if(g_preview_blobs[i].merged)mg++;
    wchar_t info[384];
    if(missed_dots>0)
        swprintf(info,384,L"thresh=%d  area>=%d  |  %d dots, %d merged, %d missed  |  smallest=%d px",
            thresh,min_area,g_preview_nblobs,mg,missed_dots,
            g_preview_nblobs>0?g_preview_min_area_detected:0);
    else
        swprintf(info,384,L"thresh=%d  area>=%d  |  %d dots, %d merged  |  smallest=%d px",
            thresh,min_area,g_preview_nblobs,mg,
            g_preview_nblobs>0?g_preview_min_area_detected:0);
    SetWindowTextW(g_label_preview,info);
}

static void paint_preview(HWND hwnd){
    PAINTSTRUCT ps;HDC hdc=BeginPaint(hwnd,&ps);
    RECT rc;GetClientRect(hwnd,&rc);
    int pw=rc.right,ph=rc.bottom;

    /* Double-buffer: paint to offscreen bitmap, then blit */
    HDC memdc=CreateCompatibleDC(hdc);
    HBITMAP membm=CreateCompatibleBitmap(hdc,pw,ph);
    HBITMAP oldbm=(HBITMAP)SelectObject(memdc,membm);

    if(!g_preview_valid||!g_preview_rgb){
        FillRect(memdc,&rc,(HBRUSH)GetStockObject(LTGRAY_BRUSH));
        SetBkMode(memdc,TRANSPARENT);
        DrawTextW(memdc,L"No preview.\nSelect a folder with PGM files.",-1,&rc,
            DT_CENTER|DT_VCENTER|DT_WORDBREAK);
    } else {
        int iw=g_preview_img.width,ih=g_preview_img.height;
        /* Base scale: fit to panel, cap at 1:1 */
        double bs=1.0;
        {double fx=(double)pw/iw,fy=(double)ph/ih;bs=(fx<fy)?fx:fy;if(bs>1.0)bs=1.0;}
        double es=bs*g_zoom;

        double vis_w=pw/es,vis_h=ph/es;
        double cx=iw/2.0+g_pan_x,cy=ih/2.0+g_pan_y;
        if(cx<vis_w/2)cx=vis_w/2;if(cx>iw-vis_w/2)cx=iw-vis_w/2;
        if(cy<vis_h/2)cy=vis_h/2;if(cy>ih-vis_h/2)cy=ih-vis_h/2;
        g_pan_x=cx-iw/2.0;g_pan_y=cy-ih/2.0;

        int src_x=(int)(cx-vis_w/2),src_y=(int)(cy-vis_h/2);
        int src_w=(int)vis_w,src_h=(int)vis_h;
        if(src_x<0)src_x=0;if(src_y<0)src_y=0;
        if(src_w>iw)src_w=iw;if(src_h>ih)src_h=ih;
        if(src_x+src_w>iw)src_x=iw-src_w;if(src_y+src_h>ih)src_y=ih-src_h;

        BITMAPINFO bmi;memset(&bmi,0,sizeof(bmi));
        bmi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth=iw;bmi.bmiHeader.biHeight=-ih;
        bmi.bmiHeader.biPlanes=1;bmi.bmiHeader.biBitCount=24;
        bmi.bmiHeader.biCompression=BI_RGB;

        /* Fill entire panel with neutral gray for letterbox bars */
        {HBRUSH grBr=CreateSolidBrush(RGB(128,128,128));
        FillRect(memdc,&rc,grBr);DeleteObject(grBr);}

        /* Calculate destination rect preserving aspect ratio */
        int dst_x=0,dst_y=0,dst_w=pw,dst_h=ph;
        {double src_aspect=(double)src_w/(double)src_h;
         double pnl_aspect=(double)pw/(double)ph;
         if(pnl_aspect>src_aspect){
             /* Panel wider than source: pillarbox (gray bars left/right) */
             dst_w=(int)(ph*src_aspect);
             dst_x=(pw-dst_w)/2;
         }else{
             /* Panel taller than source: letterbox (gray bars top/bottom) */
             dst_h=(int)(pw/src_aspect);
             dst_y=(ph-dst_h)/2;
         }}

        SetStretchBltMode(memdc,HALFTONE);
        StretchDIBits(memdc,dst_x,dst_y,dst_w,dst_h,src_x,src_y,src_w,src_h,
            g_preview_rgb,&bmi,DIB_RGB_COLORS,SRCCOPY);
    }

    /* Blit offscreen buffer to screen */
    BitBlt(hdc,0,0,pw,ph,memdc,0,0,SRCCOPY);
    SelectObject(memdc,oldbm);
    DeleteObject(membm);
    DeleteDC(memdc);
    EndPaint(hwnd,&ps);
}

static void update_imgnum_label(void){
    if(g_preview_nfiles==0){SetWindowTextW(g_label_imgnum,L"No images");return;}
    const char *bn=strrchr(g_preview_files[g_preview_index],'\\');
    if(bn)bn++;else bn=g_preview_files[g_preview_index];
    char buf[320];snprintf(buf,320,"%d / %d : %s",g_preview_index+1,g_preview_nfiles,bn);
    wchar_t wb[320];MultiByteToWideChar(CP_ACP,0,buf,-1,wb,320);
    SetWindowTextW(g_label_imgnum,wb);
}

static void reset_zoom(void){g_zoom=1.0;g_pan_x=g_pan_y=0;}

static void load_preview_at_index(void){
    g_preview_valid=0;pgm_free(&g_preview_img);
    if(g_preview_rgb){free(g_preview_rgb);g_preview_rgb=NULL;}
    reset_zoom();
    if(g_preview_nfiles==0){InvalidateRect(g_preview_panel,NULL,FALSE);return;}
    if(g_preview_index<0)g_preview_index=0;
    if(g_preview_index>=g_preview_nfiles)g_preview_index=g_preview_nfiles-1;
    if(!pgm_load(g_preview_files[g_preview_index],&g_preview_img)){
        InvalidateRect(g_preview_panel,NULL,FALSE);return;}
    g_preview_rgb=(uint8_t*)malloc(g_preview_img.width*g_preview_img.height*3);
    if(!g_preview_rgb){pgm_free(&g_preview_img);return;}
    g_preview_valid=1;build_preview_rgb();update_imgnum_label();
    InvalidateRect(g_preview_panel,NULL,FALSE);
}

static void scan_folder_for_preview(void){
    wchar_t fw[MAX_PATH_LEN];char fa[MAX_PATH_LEN];
    GetWindowTextW(g_edit_folder,fw,MAX_PATH_LEN);
    WideCharToMultiByte(CP_ACP,0,fw,-1,fa,MAX_PATH_LEN,NULL,NULL);
    g_preview_nfiles=find_pgm_files(fa,g_preview_files,MAX_FILES);
    g_preview_index=0;load_preview_at_index();
}

static void schedule_preview(void){
    KillTimer(g_hwnd,TIMER_PREVIEW);SetTimer(g_hwnd,TIMER_PREVIEW,TIMER_DELAY_MS,NULL);}

/* ===== SLIDER ↔ EDIT SYNC ===== */
static void sync_slider_to_edit(HWND slider, HWND edit){
    if(g_updating)return;g_updating=1;
    int v=(int)SendMessageW(slider,TBM_GETPOS,0,0);
    wchar_t b[32];swprintf(b,32,L"%d",v);SetWindowTextW(edit,b);
    g_updating=0;
}
static void sync_edit_to_slider(HWND edit, HWND slider, int lo, int hi){
    if(g_updating)return;g_updating=1;
    wchar_t b[32];GetWindowTextW(edit,b,32);
    int v=_wtoi(b);if(v<lo)v=lo;if(v>hi)v=hi;
    SendMessageW(slider,TBM_SETPOS,TRUE,v);
    g_updating=0;
}

/* ===== MAIN PROCESSING ===== */
static void set_status(const char *t){
    wchar_t w[1024];MultiByteToWideChar(CP_ACP,0,t,-1,w,1024);
    SetWindowTextW(g_status,w);UpdateWindow(g_status);}

static void process_images(void){
    wchar_t fw[MAX_PATH_LEN];char fa[MAX_PATH_LEN];
    GetWindowTextW(g_edit_folder,fw,MAX_PATH_LEN);
    WideCharToMultiByte(CP_ACP,0,fw,-1,fa,MAX_PATH_LEN,NULL,NULL);
    if(!strlen(fa)){MessageBoxW(g_hwnd,L"Select a folder first.",L"Error",MB_OK|MB_ICONERROR);return;}
    wchar_t pw[64];char pa[64];GetWindowTextW(g_edit_pxmm,pw,64);
    WideCharToMultiByte(CP_ACP,0,pw,-1,pa,64,NULL,NULL);
    double px_mm=atof(pa);
    if(px_mm<=0){MessageBoxW(g_hwnd,L"Enter valid pixels/mm (> 0).",L"Error",MB_OK|MB_ICONERROR);return;}
    int auto_th=(SendMessageW(g_check_auto,BM_GETCHECK,0,0)==BST_CHECKED);
    int manual_th=(int)SendMessageW(g_slider_thresh,TBM_GETPOS,0,0);
    int min_area=(int)SendMessageW(g_slider_minarea,TBM_GETPOS,0,0);
    int erosion_r=(int)SendMessageW(g_slider_erosion,TBM_GETPOS,0,0);
    int mode=(int)SendMessageW(g_combo_mode,CB_GETCURSEL,0,0);if(mode<0)mode=MODE_BBOX;
    int gridpat=(int)SendMessageW(g_combo_gridpat,CB_GETCURSEL,0,0);if(gridpat<0)gridpat=GRIDPAT_RECT;
    save_config();

    static char files[MAX_FILES][MAX_PATH_LEN];
    int nfiles=find_pgm_files(fa,files,MAX_FILES);
    if(!nfiles){MessageBoxW(g_hwnd,L"No .pgm files found.",L"Error",MB_OK|MB_ICONERROR);return;}
    {char b[256];snprintf(b,256,"Found %d PGM files. Processing...",nfiles);set_status(b);}
    SendMessageW(g_progress,PBM_SETRANGE32,0,nfiles);SendMessageW(g_progress,PBM_SETPOS,0,0);

    char of[MAX_PATH_LEN];snprintf(of,MAX_PATH_LEN,"%s\\annotated",fa);CreateDirectoryA(of,NULL);
    char cp[MAX_PATH_LEN];snprintf(cp,MAX_PATH_LEN,"%s\\dot_measurements.csv",fa);
    FILE *csv=fopen(cp,"w");
    if(!csv){MessageBoxW(g_hwnd,L"Cannot create CSV.",L"Error",MB_OK|MB_ICONERROR);return;}
    fprintf(csv,"File,Dot_Index,Centroid_X,Centroid_Y,"
        "BBox_W_px,BBox_H_px,BBox_Diam_px,BBox_Diam_mm,"
        "Body_Major_px,Body_Diam_mm,"
        "Area_px,Circularity_Raw,Circularity_Body,"
        "Grid_Row,Grid_Col,Offset_X_mm,Offset_Y_mm,Distance_Error_mm,Merged_Flag\n");

    int total_missed=0;

    stats_t gs_d,gs_cr,gs_cb,gs_ox,gs_oy,gs_dist;
    si(&gs_d,50000);si(&gs_cr,50000);si(&gs_cb,50000);si(&gs_ox,50000);si(&gs_oy,50000);si(&gs_dist,50000);
    int td=0,tm=0;

    /* Grid params from best image */
    grid_params_t gp={0};
    {int bfi=0,bc=0;
    for(int fi=0;fi<nfiles&&fi<10;fi++){pgm_image_t img;
        if(!pgm_load(files[fi],&img))continue;
        int th=auto_th?compute_otsu(img.pixels,img.width*img.height):manual_th;
        static blob_t tb[MAX_BLOBS];
        int nb=process_image_light(&img,th,min_area,tb,MAX_BLOBS);
        int gd=0;for(int i=0;i<nb;i++)if(!tb[i].merged)gd++;
        if(gd>bc){bc=gd;bfi=fi;}pgm_free(&img);}
    pgm_image_t img;
    if(pgm_load(files[bfi],&img)){
        int th=auto_th?compute_otsu(img.pixels,img.width*img.height):manual_th;
        static blob_t tb[MAX_BLOBS];
        int nb=process_image_full(&img,th,min_area,erosion_r,tb,MAX_BLOBS);
        if(gridpat==GRIDPAT_STAGGERED)
            infer_grid_params_checker(tb,nb,&gp);
        else
            infer_grid_params(tb,nb,&gp,gridpat);
        pgm_free(&img);}}

    for(int fi=0;fi<nfiles;fi++){
        pgm_image_t img;if(!pgm_load(files[fi],&img)){
            SendMessageW(g_progress,PBM_SETPOS,fi+1,0);continue;}
        int thresh=auto_th?compute_otsu(img.pixels,img.width*img.height):manual_th;
        static blob_t blobs[MAX_BLOBS];
        int nb=process_image_full(&img,thresh,min_area,erosion_r,blobs,MAX_BLOBS);
        for(int i=0;i<nb;i++){blobs[i].diameter_mm=(double)blobs[i].diameter_px/px_mm;
            blobs[i].body_diameter_mm=blobs[i].body_major_px/px_mm;}
        compute_grid_offsets(blobs,nb,&gp,px_mm,mode==MODE_BODY);
        int file_missed=0;
        if(gp.valid) file_missed=count_missed_dots(blobs,nb,&gp,img.width,img.height);
        total_missed+=file_missed;
        const char *bn=strrchr(files[fi],'\\');if(bn)bn++;else bn=files[fi];
        stats_t fs;si(&fs,nb+1);
        for(int i=0;i<nb;i++){blob_t *b=&blobs[i];
            double pd=(mode==MODE_BODY)?b->body_diameter_mm:b->diameter_mm;
            double dist_err=b->grid_valid?sqrt(b->offset_x_mm*b->offset_x_mm+b->offset_y_mm*b->offset_y_mm):0.0;
            fprintf(csv,"%s,%d,%d,%d,%d,%d,%d,%.4f,%.1f,%.4f,%d,%.3f,%.3f,%d,%d,%.4f,%.4f,%.4f,%s\n",
                bn,i+1,b->cx,b->cy,b->bb_w,b->bb_h,b->diameter_px,b->diameter_mm,
                b->body_major_px,b->body_diameter_mm,b->area,b->circularity_raw,b->circularity_body,
                b->grid_valid?b->grid_row:-1,b->grid_valid?b->grid_col:-1,
                b->grid_valid?b->offset_x_mm:0.0,b->grid_valid?b->offset_y_mm:0.0,
                b->grid_valid?dist_err:0.0,
                b->merged?"YES":"NO");
            if(!b->merged){sa(&gs_d,pd);sa(&fs,pd);
                sa(&gs_cr,b->circularity_raw);sa(&gs_cb,b->circularity_body);
                if(b->grid_valid){sa(&gs_ox,fabs(b->offset_x_mm));sa(&gs_oy,fabs(b->offset_y_mm));
                    sa(&gs_dist,dist_err);}}
            td++;if(b->merged)tm++;}
        if(fs.count>0){fprintf(csv,"%s,SUMMARY,,,,,,,,,,,,,,,,,\n",bn);
            fprintf(csv,"%s,Count,%d,,,,,,,,,,,,,,,\n",bn,fs.count);
            fprintf(csv,"%s,Missed,%d,,,,,,,,,,,,,,,\n",bn,file_missed);
            fprintf(csv,"%s,Mean,,,,,,,,%.4f,,,,,,,,\n",bn,smean(&fs));
            fprintf(csv,"%s,Median,,,,,,,,%.4f,,,,,,,,\n",bn,smed(&fs));
            fprintf(csv,"%s,StdDev,,,,,,,,%.4f,,,,,,,,\n",bn,sstd(&fs));
            fprintf(csv,"%s,Min,,,,,,,,%.4f,,,,,,,,\n",bn,fs.min_val);
            fprintf(csv,"%s,Max,,,,,,,,%.4f,,,,,,,,\n",bn,fs.max_val);}
        sfree(&fs);

        /* Annotate */
        for(int i=0;i<nb;i++){blob_t *b=&blobs[i];
            int bx0,by0,bx1,by1;
            if(mode==MODE_BODY){bx0=b->body_min_x-BORDER_PAD;by0=b->body_min_y-BORDER_PAD;
                bx1=b->body_max_x+BORDER_PAD;by1=b->body_max_y+BORDER_PAD;
            }else{bx0=b->min_x-BORDER_PAD;by0=b->min_y-BORDER_PAD;
                bx1=b->max_x+BORDER_PAD;by1=b->max_y+BORDER_PAD;}
            if(bx0<0)bx0=0;if(by0<0)by0=0;if(bx1>=img.width)bx1=img.width-1;if(by1>=img.height)by1=img.height-1;
            drect(&img,bx0,by0,bx1,by1,255);if(b->merged)drect(&img,bx0+1,by0+1,bx1-1,by1-1,255);
            char label[32];double dd=(mode==MODE_BODY)?b->body_diameter_mm:b->diameter_mm;
            if(b->merged)snprintf(label,32,"MRGD");else snprintf(label,32,"%.2f",dd);
            int tw=(int)strlen(label)*(FONT_W+1);
            int tx=b->cx-tw/2,ty=by1-FONT_H-2;
            if(tx<bx0+2)tx=bx0+2;if(tx+tw>bx1-2)tx=bx1-tw-2;if(ty<by0+2)ty=by0+2;
            uint8_t tc2=tcol(&img,tx,ty,tx+tw,ty+FONT_H);
            for(int py=ty-1;py<=ty+FONT_H;py++)for(int px=tx-1;px<=tx+tw;px++)
                dpx(&img,px,py,(tc2==255)?0:200);
            dstr(&img,tx,ty,label,tc2);}
        char op[MAX_PATH_LEN];snprintf(op,MAX_PATH_LEN,"%s\\%s",of,bn);
        pgm_save(op,&img);pgm_free(&img);
        SendMessageW(g_progress,PBM_SETPOS,fi+1,0);
        {char b[320];snprintf(b,320,"Processed %d/%d: %s (%d dots)",fi+1,nfiles,bn,nb);set_status(b);}
        MSG msg;while(PeekMessageW(&msg,NULL,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);}
    }

    fprintf(csv,"\n\nGLOBAL SUMMARY\n");
    fprintf(csv,"Total Files,%d\n",nfiles);
    fprintf(csv,"Total Dots (non-merged),%d\n",gs_d.count);
    fprintf(csv,"Total Merged,%d\n",tm);
    fprintf(csv,"Total Missed,%d\n",total_missed);
    fprintf(csv,"Mode,%s\n",mode==MODE_BODY?"Body Detection":"Bounding Box");
    fprintf(csv,"Grid Pattern,%s\n",gridpat==GRIDPAT_STAGGERED?"Checker / Staggered":"Rectangular");
    fprintf(csv,"Pixels/mm,%.4f\n",px_mm);
    if(gp.valid){fprintf(csv,"Grid Spacing X (px),%.2f\n",gp.spacing_x);
        fprintf(csv,"Grid Spacing Y (px),%.2f\n",gp.spacing_y);
        fprintf(csv,"Grid Angle (deg),%.3f\n",gp.angle*180.0/PI);
        if(gp.staggered&&fabs(gp.stagger_y)>0.01)
            fprintf(csv,"Stagger Y (px),%.2f\n",gp.stagger_y);}
    if(gs_d.count>0){fprintf(csv,"\nDiameter (mm)\n");
        fprintf(csv,"Mean,%.4f\nMedian,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_d),smed(&gs_d),sstd(&gs_d),gs_d.min_val,gs_d.max_val);}
    if(gs_cr.count>0){fprintf(csv,"\nCircularity Raw\n");
        fprintf(csv,"Mean,%.4f\nMedian,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_cr),smed(&gs_cr),sstd(&gs_cr),gs_cr.min_val,gs_cr.max_val);}
    if(gs_cb.count>0){fprintf(csv,"\nCircularity Body\n");
        fprintf(csv,"Mean,%.4f\nMedian,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_cb),smed(&gs_cb),sstd(&gs_cb),gs_cb.min_val,gs_cb.max_val);}
    if(gs_ox.count>0){fprintf(csv,"\nGrid Offset X Abs (mm)\nMean,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
        smean(&gs_ox),sstd(&gs_ox),gs_ox.min_val,gs_ox.max_val);
        fprintf(csv,"\nGrid Offset Y Abs (mm)\nMean,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
        smean(&gs_oy),sstd(&gs_oy),gs_oy.min_val,gs_oy.max_val);}
    if(gs_dist.count>0){fprintf(csv,"\nDistance Error (mm)\nMean,%.4f\nMedian,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
        smean(&gs_dist),smed(&gs_dist),sstd(&gs_dist),gs_dist.min_val,gs_dist.max_val);}
    fclose(csv);

    char ma[1024];snprintf(ma,sizeof(ma),
        "Done! %d files, %d dots (%d merged, %d missed).\r\n\r\n"
        "Diameter (%s): Mean=%.4f  Median=%.4f  StdDev=%.4f\r\n"
        "  Min=%.4f  Max=%.4f mm\r\n\r\n"
        "Circularity: Mean=%.3f  StdDev=%.3f\r\n"
        "Avg Abs Offset: X=%.4f  Y=%.4f mm\r\n"
        "Distance Error: Mean=%.4f  StdDev=%.4f mm\r\n\r\n"
        "CSV: %s\r\nAnnotated: %s\\",
        nfiles,td,tm,total_missed,mode==MODE_BODY?"Body":"BBox",
        smean(&gs_d),smed(&gs_d),sstd(&gs_d),
        gs_d.count>0?gs_d.min_val:0.0,gs_d.count>0?gs_d.max_val:0.0,
        gs_cb.count>0?smean(&gs_cb):0.0,gs_cb.count>0?sstd(&gs_cb):0.0,
        gs_ox.count>0?smean(&gs_ox):0.0,gs_oy.count>0?smean(&gs_oy):0.0,
        gs_dist.count>0?smean(&gs_dist):0.0,gs_dist.count>0?sstd(&gs_dist):0.0,
        cp,of);
    wchar_t mw[1024];MultiByteToWideChar(CP_ACP,0,ma,-1,mw,1024);
    set_status(ma);MessageBoxW(g_hwnd,mw,L"Processing Complete",MB_OK|MB_ICONINFORMATION);
    sfree(&gs_d);sfree(&gs_cr);sfree(&gs_cb);sfree(&gs_ox);sfree(&gs_oy);sfree(&gs_dist);
}

/* ===== FOLDER BROWSE ===== */
static void browse_folder(HWND hwnd){
    BROWSEINFOW bi={0};bi.hwndOwner=hwnd;
    bi.lpszTitle=L"Select folder containing PGM images";
    bi.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl=SHBrowseForFolderW(&bi);
    if(pidl){wchar_t p[MAX_PATH];
        if(SHGetPathFromIDListW(pidl,p)){SetWindowTextW(g_edit_folder,p);scan_folder_for_preview();}
        CoTaskMemFree(pidl);}
}

/* ===== PREVIEW SUBCLASS ===== */
static WNDPROC g_orig_preview_proc;

/* Convert panel coordinates (mx,my) to image coordinates (ix,iy).
   Returns 1 if the point is within the image, 0 if outside. */
static int panel_to_image(HWND hwnd, int mx, int my, double *ix, double *iy){
    if(!g_preview_valid||!g_preview_rgb) return 0;
    RECT rc;GetClientRect(hwnd,&rc);
    int pw=rc.right,ph=rc.bottom;
    int iw=g_preview_img.width,ih=g_preview_img.height;
    double bs=1.0;
    {double fx=(double)pw/iw,fy=(double)ph/ih;bs=(fx<fy)?fx:fy;if(bs>1.0)bs=1.0;}
    double es=bs*g_zoom;
    double vis_w=pw/es,vis_h=ph/es;
    double cx=iw/2.0+g_pan_x,cy=ih/2.0+g_pan_y;
    if(cx<vis_w/2)cx=vis_w/2;if(cx>iw-vis_w/2)cx=iw-vis_w/2;
    if(cy<vis_h/2)cy=vis_h/2;if(cy>ih-vis_h/2)cy=ih-vis_h/2;
    int src_x=(int)(cx-vis_w/2),src_y=(int)(cy-vis_h/2);
    int src_w=(int)vis_w,src_h=(int)vis_h;
    if(src_x<0)src_x=0;if(src_y<0)src_y=0;
    if(src_w>iw)src_w=iw;if(src_h>ih)src_h=ih;
    if(src_x+src_w>iw)src_x=iw-src_w;if(src_y+src_h>ih)src_y=ih-src_h;
    /* Compute destination rect (same logic as paint_preview) */
    int dst_x=0,dst_y=0,dst_w=pw,dst_h=ph;
    {double src_aspect=(double)src_w/(double)src_h;
     double pnl_aspect=(double)pw/(double)ph;
     if(pnl_aspect>src_aspect){dst_w=(int)(ph*src_aspect);dst_x=(pw-dst_w)/2;}
     else{dst_h=(int)(pw/src_aspect);dst_y=(ph-dst_h)/2;}}
    if(mx<dst_x||mx>=dst_x+dst_w||my<dst_y||my>=dst_y+dst_h) return 0;
    *ix=src_x+(double)(mx-dst_x)*src_w/dst_w;
    *iy=src_y+(double)(my-dst_y)*src_h/dst_h;
    return 1;
}

/* Find blob index at image coordinates. Returns -1 if none found. */
static int find_blob_at(double ix, double iy, int mode){
    for(int i=0;i<g_preview_nblobs;i++){
        int bx0,by0,bx1,by1;
        blob_t *b=&g_preview_blobs[i];
        if(mode==MODE_BODY){
            bx0=b->body_min_x;by0=b->body_min_y;bx1=b->body_max_x;by1=b->body_max_y;
        }else{
            bx0=b->min_x;by0=b->min_y;bx1=b->max_x;by1=b->max_y;
        }
        /* Add a small margin for easier targeting */
        bx0-=3;by0-=3;bx1+=3;by1+=3;
        if(ix>=bx0&&ix<=bx1&&iy>=by0&&iy<=by1) return i;
    }
    return -1;
}

static LRESULT CALLBACK PreviewProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam){
    switch(msg){
    case WM_PAINT: paint_preview(hwnd); return 0;
    case WM_ERASEBKGND: return 1; /* suppress background erase — we double-buffer */
    case WM_MOUSEWHEEL:
        if(g_zoom_active&&g_preview_valid){
            int delta=GET_WHEEL_DELTA_WPARAM(wParam);
            if(delta>0){g_zoom*=1.25;if(g_zoom>16.0)g_zoom=16.0;}
            else{g_zoom/=1.25;if(g_zoom<1.0)g_zoom=1.0;}
            if(g_zoom<=1.01){g_pan_x=g_pan_y=0;}
            InvalidateRect(hwnd,NULL,FALSE);return 0;}
        break;
    case WM_LBUTTONDOWN:
        if(g_zoom_active&&g_zoom>1.01){
            g_dragging=1;g_drag_mx=LOWORD(lParam);g_drag_my=HIWORD(lParam);
            g_drag_px=g_pan_x;g_drag_py=g_pan_y;SetCapture(hwnd);return 0;}
        break;
    case WM_MOUSEMOVE:
        if(g_dragging){
            RECT rc;GetClientRect(hwnd,&rc);
            int iw=g_preview_img.width,ih=g_preview_img.height;
            double bs=1.0;{double fx=(double)rc.right/iw,fy=(double)rc.bottom/ih;
                bs=(fx<fy)?fx:fy;if(bs>1.0)bs=1.0;}
            double es=bs*g_zoom;
            int dx=LOWORD(lParam)-g_drag_mx,dy=HIWORD(lParam)-g_drag_my;
            g_pan_x=g_drag_px-dx/es;g_pan_y=g_drag_py+dy/es;
            InvalidateRect(hwnd,NULL,FALSE);return 0;}
        /* Tooltip: hit-test blobs under cursor */
        if(g_tooltip&&g_preview_valid&&g_preview_nblobs>0){
            int mx=(short)LOWORD(lParam),my=(short)HIWORD(lParam);
            double img_x,img_y;
            int mode=get_mode();if(mode<0)mode=MODE_BBOX;
            if(panel_to_image(hwnd,mx,my,&img_x,&img_y)){
                int bi=find_blob_at(img_x,img_y,mode);
                if(bi>=0&&bi!=g_hover_blob_idx){
                    g_hover_blob_idx=bi;
                    blob_t *b=&g_preview_blobs[bi];
                    wchar_t tip[128];
                    swprintf(tip,128,L"Area: %d px\nDiam: %d px%s",
                        b->area,b->diameter_px,b->merged?L"\n[MERGED]":L"");
                    TOOLINFOW ti;memset(&ti,0,sizeof(ti));
                    ti.cbSize=sizeof(ti);ti.hwnd=hwnd;ti.uId=0;ti.lpszText=tip;
                    SendMessageW(g_tooltip,TTM_UPDATETIPTEXTW,0,(LPARAM)&ti);
                    POINT pt;GetCursorPos(&pt);
                    SendMessageW(g_tooltip,TTM_TRACKPOSITION,0,MAKELONG(pt.x+16,pt.y+16));
                    SendMessageW(g_tooltip,TTM_TRACKACTIVATE,TRUE,(LPARAM)&ti);
                }else if(bi<0&&g_hover_blob_idx>=0){
                    g_hover_blob_idx=-1;
                    TOOLINFOW ti;memset(&ti,0,sizeof(ti));
                    ti.cbSize=sizeof(ti);ti.hwnd=hwnd;ti.uId=0;
                    SendMessageW(g_tooltip,TTM_TRACKACTIVATE,FALSE,(LPARAM)&ti);
                }else if(bi>=0){
                    /* Same blob, just update position */
                    POINT pt;GetCursorPos(&pt);
                    SendMessageW(g_tooltip,TTM_TRACKPOSITION,0,MAKELONG(pt.x+16,pt.y+16));
                }
            }else if(g_hover_blob_idx>=0){
                g_hover_blob_idx=-1;
                TOOLINFOW ti;memset(&ti,0,sizeof(ti));
                ti.cbSize=sizeof(ti);ti.hwnd=hwnd;ti.uId=0;
                SendMessageW(g_tooltip,TTM_TRACKACTIVATE,FALSE,(LPARAM)&ti);
            }
            /* Request WM_MOUSELEAVE so we can hide tooltip when cursor leaves */
            TRACKMOUSEEVENT tme;memset(&tme,0,sizeof(tme));
            tme.cbSize=sizeof(tme);tme.dwFlags=TME_LEAVE;tme.hwndTrack=hwnd;
            TrackMouseEvent(&tme);
        }
        break;
    case WM_MOUSELEAVE:
        if(g_tooltip&&g_hover_blob_idx>=0){
            g_hover_blob_idx=-1;
            TOOLINFOW ti;memset(&ti,0,sizeof(ti));
            ti.cbSize=sizeof(ti);ti.hwnd=hwnd;ti.uId=0;
            SendMessageW(g_tooltip,TTM_TRACKACTIVATE,FALSE,(LPARAM)&ti);
        }
        break;
    case WM_LBUTTONUP:
        if(g_dragging){g_dragging=0;ReleaseCapture();return 0;}
        break;
    }
    return CallWindowProcW(g_orig_preview_proc,hwnd,msg,wParam,lParam);
}

/* ===== TRACKBAR SUBCLASS — eat all keyboard input, refuse focus ===== */
static WNDPROC g_orig_trackbar_proc;
static LRESULT CALLBACK TrackbarNoKbProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam){
    if(msg==WM_KEYDOWN||msg==WM_KEYUP||msg==WM_CHAR||msg==WM_SYSKEYDOWN||msg==WM_SYSKEYUP) return 0;
    if(msg==WM_GETDLGCODE) return 0;
    if(msg==WM_SETFOCUS){SetFocus(g_hwnd);return 0;} /* redirect focus to main window */
    return CallWindowProcW(g_orig_trackbar_proc,hwnd,msg,wParam,lParam);
}

/* ===== LAYOUT HELPERS ===== */
static void reposition_preview(int client_w, int client_h){
    int px=LEFT_W+MARGIN;
    int nav_y=MARGIN;
    MoveWindow(g_btn_prev,px,nav_y,30,22,TRUE);
    MoveWindow(g_btn_next,px+34,nav_y,30,22,TRUE);
    int zoom_x=px+72;
    MoveWindow(g_btn_zoom,zoom_x,nav_y,52,22,TRUE);
    MoveWindow(g_btn_zoomreset,zoom_x+56,nav_y,52,22,TRUE);
    int label_x=zoom_x+116;
    int label_w=client_w-label_x-MARGIN;if(label_w<50)label_w=50;
    MoveWindow(g_label_imgnum,label_x,nav_y+3,label_w,20,TRUE);
    int info_y=nav_y+26;
    int prev_w=client_w-px-MARGIN;if(prev_w<100)prev_w=100;
    MoveWindow(g_label_preview,px,info_y,prev_w,20,TRUE);
    int prev_y=info_y+22;
    int prev_h=client_h-prev_y-MARGIN;if(prev_h<100)prev_h=100;
    MoveWindow(g_preview_panel,px,prev_y,prev_w,prev_h,FALSE);
    InvalidateRect(g_preview_panel,NULL,FALSE);
}

/* ===== WINDOW PROCEDURE ===== */
static void update_auto_state(void){
    int on=(SendMessageW(g_check_auto,BM_GETCHECK,0,0)==BST_CHECKED);
    EnableWindow(g_slider_thresh,!on);EnableWindow(g_edit_thresh,!on);
    EnableWindow(g_label_thresh,!on);schedule_preview();}
static void update_mode_state(void){
    int body=(get_mode()==MODE_BODY);
    EnableWindow(g_slider_erosion,body);EnableWindow(g_edit_erosion,body);
    EnableWindow(g_label_erosion,body);schedule_preview();}

static BOOL CALLBACK SetFontCB(HWND h,LPARAM l){SendMessageW(h,WM_SETFONT,(WPARAM)l,TRUE);return TRUE;}

static LRESULT CALLBACK WndProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam){
    switch(msg){
    case WM_CREATE:{
        int lx=15,cx=160,cw=280,bw=75,rh=26;
        int ex=105,ew=50; /* edit x offset from lx, edit width */
        int sx=cx,sw=cw;  /* slider x and width */
        int y=10;

        /* Folder */
        CreateWindowW(L"STATIC",L"Image Folder:",WS_VISIBLE|WS_CHILD,lx,y+4,120,20,hwnd,NULL,g_hinst,NULL);
        g_edit_folder=CreateWindowW(L"EDIT",L"",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL|ES_READONLY,
            cx,y,cw-bw-8,24,hwnd,(HMENU)ID_EDIT_FOLDER,g_hinst,NULL);
        CreateWindowW(L"BUTTON",L"Browse...",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            cx+cw-bw,y,bw,24,hwnd,(HMENU)ID_BTN_BROWSE,g_hinst,NULL);
        y+=rh+4;

        /* Pixels/mm */
        CreateWindowW(L"STATIC",L"Pixels per mm:",WS_VISIBLE|WS_CHILD,lx,y+4,130,20,hwnd,NULL,g_hinst,NULL);
        g_edit_pxmm=CreateWindowW(L"EDIT",L"10.0",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL,
            cx,y,80,24,hwnd,(HMENU)ID_EDIT_PXMM,g_hinst,NULL);
        y+=rh+4;

        /* Mode */
        CreateWindowW(L"STATIC",L"Measurement mode:",WS_VISIBLE|WS_CHILD,lx,y+4,140,20,hwnd,NULL,g_hinst,NULL);
        g_combo_mode=CreateWindowW(L"COMBOBOX",NULL,WS_VISIBLE|WS_CHILD|CBS_DROPDOWNLIST|WS_VSCROLL,
            cx,y,170,120,hwnd,(HMENU)ID_COMBO_MODE,g_hinst,NULL);
        SendMessageW(g_combo_mode,CB_ADDSTRING,0,(LPARAM)L"Bounding Box");
        SendMessageW(g_combo_mode,CB_ADDSTRING,0,(LPARAM)L"Body Detection");
        SendMessageW(g_combo_mode,CB_SETCURSEL,MODE_BBOX,0);
        y+=rh+6;

        /* Auto threshold */
        g_check_auto=CreateWindowW(L"BUTTON",L"Auto threshold (Otsu)",WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX,
            lx,y,200,20,hwnd,(HMENU)ID_CHECK_AUTO,g_hinst,NULL);
        SendMessageW(g_check_auto,BM_SETCHECK,BST_CHECKED,0);
        y+=rh;

        /* Threshold: label + edit + slider */
        g_label_thresh=CreateWindowW(L"STATIC",L"Threshold:",WS_VISIBLE|WS_CHILD,
            lx,y+4,90,20,hwnd,(HMENU)ID_LABEL_THRESH,g_hinst,NULL);
        g_edit_thresh=CreateWindowW(L"EDIT",L"100",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_NUMBER|WS_TABSTOP,
            lx+ex,y+2,ew,22,hwnd,(HMENU)ID_EDIT_THRESH,g_hinst,NULL);
        g_slider_thresh=CreateWindowW(TRACKBAR_CLASSW,NULL,WS_VISIBLE|WS_CHILD|TBS_HORZ|TBS_AUTOTICKS,
            sx,y,sw,28,hwnd,(HMENU)ID_SLIDER_THRESH,g_hinst,NULL);
        SendMessageW(g_slider_thresh,TBM_SETRANGE,TRUE,MAKELPARAM(1,254));
        SendMessageW(g_slider_thresh,TBM_SETPOS,TRUE,100);
        SendMessageW(g_slider_thresh,TBM_SETTICFREQ,16,0);
        EnableWindow(g_slider_thresh,FALSE);EnableWindow(g_edit_thresh,FALSE);EnableWindow(g_label_thresh,FALSE);
        y+=rh+2;

        /* Min area */
        g_label_minarea=CreateWindowW(L"STATIC",L"Min area (px):",WS_VISIBLE|WS_CHILD,
            lx,y+4,100,20,hwnd,(HMENU)ID_LABEL_MINAREA,g_hinst,NULL);
        g_edit_minarea=CreateWindowW(L"EDIT",L"150",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_NUMBER|WS_TABSTOP,
            lx+ex,y+2,ew,22,hwnd,(HMENU)ID_EDIT_MINAREA,g_hinst,NULL);
        g_slider_minarea=CreateWindowW(TRACKBAR_CLASSW,NULL,WS_VISIBLE|WS_CHILD|TBS_HORZ|TBS_AUTOTICKS,
            sx,y,sw,28,hwnd,(HMENU)ID_SLIDER_MINAREA,g_hinst,NULL);
        SendMessageW(g_slider_minarea,TBM_SETRANGE,TRUE,MAKELPARAM(10,2000));
        SendMessageW(g_slider_minarea,TBM_SETPOS,TRUE,150);
        SendMessageW(g_slider_minarea,TBM_SETTICFREQ,100,0);
        y+=rh+2;

        /* Erosion */
        g_label_erosion=CreateWindowW(L"STATIC",L"Erosion (px):",WS_VISIBLE|WS_CHILD,
            lx,y+4,100,20,hwnd,(HMENU)ID_LABEL_EROSION,g_hinst,NULL);
        g_edit_erosion=CreateWindowW(L"EDIT",L"4",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_NUMBER|WS_TABSTOP,
            lx+ex,y+2,ew,22,hwnd,(HMENU)ID_EDIT_EROSION,g_hinst,NULL);
        g_slider_erosion=CreateWindowW(TRACKBAR_CLASSW,NULL,WS_VISIBLE|WS_CHILD|TBS_HORZ|TBS_AUTOTICKS,
            sx,y,sw,28,hwnd,(HMENU)ID_SLIDER_EROSION,g_hinst,NULL);
        SendMessageW(g_slider_erosion,TBM_SETRANGE,TRUE,MAKELPARAM(1,15));
        SendMessageW(g_slider_erosion,TBM_SETPOS,TRUE,4);
        SendMessageW(g_slider_erosion,TBM_SETTICFREQ,1,0);
        EnableWindow(g_slider_erosion,FALSE);EnableWindow(g_edit_erosion,FALSE);EnableWindow(g_label_erosion,FALSE);
        y+=rh+6;

        /* Checkboxes */
        g_check_cross=CreateWindowW(L"BUTTON",L"Show crosshairs",WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX,
            lx,y,150,20,hwnd,(HMENU)ID_CHECK_CROSS,g_hinst,NULL);
        g_check_grid=CreateWindowW(L"BUTTON",L"Show grid lines",WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX,
            lx+160,y,150,20,hwnd,(HMENU)ID_CHECK_GRID,g_hinst,NULL);
        y+=rh+4;

        /* Grid pattern selector */
        CreateWindowW(L"STATIC",L"Grid pattern:",WS_VISIBLE|WS_CHILD,lx,y+4,100,20,hwnd,NULL,g_hinst,NULL);
        g_combo_gridpat=CreateWindowW(L"COMBOBOX",NULL,WS_VISIBLE|WS_CHILD|CBS_DROPDOWNLIST|WS_VSCROLL,
            lx+105,y,170,80,hwnd,(HMENU)ID_COMBO_GRIDPAT,g_hinst,NULL);
        SendMessageW(g_combo_gridpat,CB_ADDSTRING,0,(LPARAM)L"Rectangular");
        SendMessageW(g_combo_gridpat,CB_ADDSTRING,0,(LPARAM)L"Checker / Staggered");
        SendMessageW(g_combo_gridpat,CB_SETCURSEL,GRIDPAT_RECT,0);
        y+=rh+4;

        /* Process */
        CreateWindowW(L"BUTTON",L"Process All Images",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            lx,y,170,34,hwnd,(HMENU)ID_BTN_PROCESS,g_hinst,NULL);
        y+=40;

        /* Progress */
        g_progress=CreateWindowW(PROGRESS_CLASSW,NULL,WS_VISIBLE|WS_CHILD|PBS_SMOOTH,
            lx,y,LEFT_W-30,18,hwnd,(HMENU)ID_PROGRESS,g_hinst,NULL);
        y+=24;

        /* Status */
        g_status=CreateWindowW(L"STATIC",L"Ready. Select a folder and configure settings.",
            WS_VISIBLE|WS_CHILD|SS_LEFT,lx,y,LEFT_W-30,44,hwnd,(HMENU)ID_STATUS,g_hinst,NULL);
        y+=48;

        /* ---- Record Mode Section ---- */
        CreateWindowW(L"STATIC",L"─── Record Mode (capture from camera) ───",
            WS_VISIBLE|WS_CHILD|SS_LEFT,lx,y,LEFT_W-30,18,hwnd,NULL,g_hinst,NULL);
        y+=22;

        /* Interface selector */
        CreateWindowW(L"STATIC",L"Interface:",WS_VISIBLE|WS_CHILD,lx,y+4,80,20,hwnd,NULL,g_hinst,NULL);
        g_combo_iface=CreateWindowW(L"COMBOBOX",NULL,WS_VISIBLE|WS_CHILD|CBS_DROPDOWNLIST|WS_VSCROLL,
            lx+82,y,LEFT_W-30-82-50,200,hwnd,(HMENU)ID_COMBO_IFACE,g_hinst,NULL);
        g_btn_refresh=CreateWindowW(L"BUTTON",L"\x21BB",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            LEFT_W-30-50+lx,y,44,24,hwnd,(HMENU)ID_BTN_REFRESH,g_hinst,NULL);
        y+=rh+2;

        /* Output folder */
        CreateWindowW(L"STATIC",L"Output folder:",WS_VISIBLE|WS_CHILD,lx,y+4,100,20,hwnd,NULL,g_hinst,NULL);
        g_edit_outfolder=CreateWindowW(L"EDIT",L"",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL|ES_READONLY,
            lx+100,y,LEFT_W-30-100-bw-8,24,hwnd,(HMENU)ID_EDIT_OUTFOLDER,g_hinst,NULL);
        CreateWindowW(L"BUTTON",L"Browse...",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            LEFT_W-30-bw+lx,y,bw,24,hwnd,(HMENU)ID_BTN_BROWSE_OUT,g_hinst,NULL);
        y+=rh+2;

        /* Stability time + MAD threshold */
        CreateWindowW(L"STATIC",L"Stable time (s):",WS_VISIBLE|WS_CHILD,lx,y+4,110,20,hwnd,NULL,g_hinst,NULL);
        g_edit_stable_sec=CreateWindowW(L"EDIT",L"0.25",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL,
            lx+112,y,50,24,hwnd,(HMENU)ID_EDIT_STABLE_SEC,g_hinst,NULL);
        CreateWindowW(L"STATIC",L"MAD thresh:",WS_VISIBLE|WS_CHILD,lx+174,y+4,82,20,hwnd,NULL,g_hinst,NULL);
        g_edit_mad_thresh=CreateWindowW(L"EDIT",L"12",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL,
            lx+258,y,40,24,hwnd,(HMENU)ID_EDIT_MAD_THRESH,g_hinst,NULL);
        y+=rh+4;

        /* Record button */
        g_btn_record=CreateWindowW(L"BUTTON",L"Start Recording",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            lx,y,140,30,hwnd,(HMENU)ID_BTN_RECORD,g_hinst,NULL);
        y+=36;

        /* Record status */
        g_label_rec_status=CreateWindowW(L"STATIC",L"Record: idle",
            WS_VISIBLE|WS_CHILD|SS_LEFT,lx,y,LEFT_W-30,36,hwnd,(HMENU)ID_LABEL_REC_STATUS,g_hinst,NULL);

        /* Right panel: nav buttons, zoom buttons, preview */
        int px2=LEFT_W+MARGIN;
        g_btn_prev=CreateWindowW(L"BUTTON",L"\x25C0",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            px2,MARGIN,30,22,hwnd,(HMENU)ID_BTN_PREV,g_hinst,NULL);
        g_btn_next=CreateWindowW(L"BUTTON",L"\x25B6",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            px2+34,MARGIN,30,22,hwnd,(HMENU)ID_BTN_NEXT,g_hinst,NULL);
        g_btn_zoom=CreateWindowW(L"BUTTON",L"Zoom",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            px2+72,MARGIN,52,22,hwnd,(HMENU)ID_BTN_ZOOM,g_hinst,NULL);
        g_btn_zoomreset=CreateWindowW(L"BUTTON",L"Reset",WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
            px2+128,MARGIN,52,22,hwnd,(HMENU)ID_BTN_ZOOMRESET,g_hinst,NULL);
        g_label_imgnum=CreateWindowW(L"STATIC",L"No images",WS_VISIBLE|WS_CHILD|SS_LEFT,
            px2+188,MARGIN+3,300,20,hwnd,(HMENU)ID_LABEL_IMGNUM,g_hinst,NULL);
        g_label_preview=CreateWindowW(L"STATIC",L"(select a folder)",WS_VISIBLE|WS_CHILD|SS_LEFT,
            px2,MARGIN+26,420,20,hwnd,(HMENU)ID_LABEL_PREVIEW,g_hinst,NULL);
        g_preview_panel=CreateWindowW(L"STATIC",NULL,WS_VISIBLE|WS_CHILD|WS_BORDER|SS_NOTIFY,
            px2,MARGIN+48,420,340,hwnd,(HMENU)ID_PREVIEW,g_hinst,NULL);
        g_orig_preview_proc=(WNDPROC)SetWindowLongPtrW(g_preview_panel,GWLP_WNDPROC,(LONG_PTR)PreviewProc);

        /* Tooltip for dot hover info */
        g_tooltip=CreateWindowExW(WS_EX_TOPMOST,TOOLTIPS_CLASSW,NULL,
            WS_POPUP|TTS_NOPREFIX|TTS_ALWAYSTIP,
            0,0,0,0,hwnd,NULL,g_hinst,NULL);
        if(g_tooltip){
            TOOLINFOW ti;memset(&ti,0,sizeof(ti));
            ti.cbSize=sizeof(ti);
            ti.uFlags=TTF_TRACK|TTF_ABSOLUTE;
            ti.hwnd=g_preview_panel;
            ti.uId=0;
            ti.lpszText=L"";
            SendMessageW(g_tooltip,TTM_ADDTOOLW,0,(LPARAM)&ti);
            SendMessageW(g_tooltip,TTM_SETMAXTIPWIDTH,0,200);
        }

        /* Subclass all trackbars to block keyboard input */
        g_orig_trackbar_proc=(WNDPROC)SetWindowLongPtrW(g_slider_thresh,GWLP_WNDPROC,(LONG_PTR)TrackbarNoKbProc);
        SetWindowLongPtrW(g_slider_minarea,GWLP_WNDPROC,(LONG_PTR)TrackbarNoKbProc);
        SetWindowLongPtrW(g_slider_erosion,GWLP_WNDPROC,(LONG_PTR)TrackbarNoKbProc);
        /* Remove WS_TABSTOP so trackbars can't receive focus via Tab key */
        {HWND tb3[3]={g_slider_thresh,g_slider_minarea,g_slider_erosion};
        for(int i=0;i<3;i++){LONG_PTR sty=GetWindowLongPtrW(tb3[i],GWL_STYLE);
            SetWindowLongPtrW(tb3[i],GWL_STYLE,sty&~WS_TABSTOP);}}

        HFONT hf=CreateFontW(16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,
            DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
        if(hf) EnumChildWindows(hwnd,SetFontCB,(LPARAM)hf);
        load_config();
        break;}

    case WM_SIZE:{
        RECT rc;GetClientRect(hwnd,&rc);
        reposition_preview(rc.right,rc.bottom);
        break;}

    case WM_GETMINMAXINFO:{
        MINMAXINFO *mm=(MINMAXINFO*)lParam;
        mm->ptMinTrackSize.x=MIN_WIN_W;mm->ptMinTrackSize.y=MIN_WIN_H;
        break;}

    case WM_TIMER:
        if(wParam==TIMER_PREVIEW){KillTimer(hwnd,TIMER_PREVIEW);
            if(g_preview_valid){build_preview_rgb();InvalidateRect(g_preview_panel,NULL,FALSE);}}
        break;

    case WM_HSCROLL:
        if((HWND)lParam==g_slider_thresh){sync_slider_to_edit(g_slider_thresh,g_edit_thresh);schedule_preview();}
        else if((HWND)lParam==g_slider_minarea){sync_slider_to_edit(g_slider_minarea,g_edit_minarea);schedule_preview();}
        else if((HWND)lParam==g_slider_erosion){sync_slider_to_edit(g_slider_erosion,g_edit_erosion);schedule_preview();}
        break;

    case WM_COMMAND:
        switch(LOWORD(wParam)){
        case ID_BTN_BROWSE:browse_folder(hwnd);break;
        case ID_BTN_PROCESS:process_images();break;
        case ID_CHECK_AUTO:update_auto_state();save_config();break;
        case ID_COMBO_MODE:if(HIWORD(wParam)==CBN_SELCHANGE){update_mode_state();save_config();}break;
        case ID_COMBO_GRIDPAT:if(HIWORD(wParam)==CBN_SELCHANGE){schedule_preview();save_config();}break;
        case ID_CHECK_CROSS:case ID_CHECK_GRID:schedule_preview();save_config();break;
        case ID_EDIT_PXMM:if(HIWORD(wParam)==EN_KILLFOCUS)save_config();break;
        case ID_EDIT_THRESH:if(HIWORD(wParam)==EN_KILLFOCUS){sync_edit_to_slider(g_edit_thresh,g_slider_thresh,1,254);schedule_preview();save_config();}break;
        case ID_EDIT_MINAREA:if(HIWORD(wParam)==EN_KILLFOCUS){sync_edit_to_slider(g_edit_minarea,g_slider_minarea,10,2000);schedule_preview();save_config();}break;
        case ID_EDIT_EROSION:if(HIWORD(wParam)==EN_KILLFOCUS){sync_edit_to_slider(g_edit_erosion,g_slider_erosion,1,15);schedule_preview();save_config();}break;
        case ID_BTN_PREV:if(g_preview_index>0){g_preview_index--;load_preview_at_index();}break;
        case ID_BTN_NEXT:if(g_preview_index<g_preview_nfiles-1){g_preview_index++;load_preview_at_index();}break;
        case ID_BTN_ZOOM:
            g_zoom_active=!g_zoom_active;
            SetWindowTextW(g_btn_zoom,g_zoom_active?L"Zoom*":L"Zoom");
            break;
        case ID_BTN_ZOOMRESET:reset_zoom();InvalidateRect(g_preview_panel,NULL,FALSE);break;
        /* Record Mode handlers */
        case ID_BTN_RECORD:
            if(g_rec_state==REC_IDLE) start_recording(); else stop_recording();
            break;
        case ID_BTN_REFRESH:refresh_interfaces();break;
        case ID_BTN_BROWSE_OUT:browse_output_folder(hwnd);break;
        }
        break;

    case WM_REC_STATUS:{
        /* Status update from recording thread (wParam=0, lParam=malloc'd wchar_t*) */
        wchar_t *msg=(wchar_t *)lParam;
        if(msg){SetWindowTextW(g_label_rec_status,msg);free(msg);}
        break;}
    
    case WM_REC_SAVED:{
        /* A frame was saved - if output dir matches analysis folder, could auto-refresh */
        break;}

    case WM_DESTROY:
        if(g_rec_state!=REC_IDLE) stop_recording();
        save_config();PostQuitMessage(0);break;
    default:return DefWindowProcW(hwnd,msg,wParam,lParam);}
    return 0;
}

/* ===== ENTRY POINT ===== */
int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrev,LPSTR lpCmd,int nShow){
    (void)hPrev;(void)lpCmd;g_hinst=hInst;
    INITCOMMONCONTROLSEX icc={sizeof(icc),ICC_BAR_CLASSES|ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&icc);CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
    InitializeCriticalSection(&g_rec_cs);

    /* Init Winsock for sockaddr_in used in interface enumeration */
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);

    WNDCLASSW wc={0};wc.lpfnWndProc=WndProc;wc.hInstance=hInst;
    wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    wc.lpszClassName=L"DotAnalyzer";
    wc.hIcon=LoadIconW(hInst,MAKEINTRESOURCEW(1));
    RegisterClassW(&wc);

    g_hwnd=CreateWindowW(L"DotAnalyzer",L"Dot Analyzer  v7.3",
        WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,CW_USEDEFAULT,CW_USEDEFAULT,MIN_WIN_W,MIN_WIN_H,
        NULL,NULL,hInst,NULL);
    ShowWindow(g_hwnd,nShow);UpdateWindow(g_hwnd);

    /* Populate interface list (non-blocking - just fills dropdown) */
    refresh_interfaces();

    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)){
        /* Eat ALL keyboard events unless focus is in an edit box.
           This prevents trackbar sliders from ever receiving arrow keys. */
        if(msg.message==WM_KEYDOWN||msg.message==WM_KEYUP||msg.message==WM_CHAR){
            HWND foc=GetFocus();
            wchar_t cls[32]={0};if(foc)GetClassNameW(foc,cls,32);
            int is_edit=(foc&&_wcsicmp(cls,L"Edit")==0);
            if(!is_edit){
                if(msg.message==WM_KEYDOWN&&msg.wParam==VK_LEFT)
                    PostMessageW(g_hwnd,WM_COMMAND,ID_BTN_PREV,0);
                if(msg.message==WM_KEYDOWN&&msg.wParam==VK_RIGHT)
                    PostMessageW(g_hwnd,WM_COMMAND,ID_BTN_NEXT,0);
                continue; /* swallow ALL non-edit keyboard events */
            }
        }
        /* Forward mouse wheel to preview if it's hovered */
        if(msg.message==WM_MOUSEWHEEL){
            POINT pt;GetCursorPos(&pt);
            if(WindowFromPoint(pt)==g_preview_panel){
                SendMessageW(g_preview_panel,msg.message,msg.wParam,msg.lParam);continue;
            }
        }
        TranslateMessage(&msg);DispatchMessageW(&msg);
    }
    pgm_free(&g_preview_img);if(g_preview_rgb)free(g_preview_rgb);
    DeleteCriticalSection(&g_rec_cs);
    if(g_wpcap_dll) FreeLibrary(g_wpcap_dll);
    WSACleanup();
    CoUninitialize();return(int)msg.wParam;
}
