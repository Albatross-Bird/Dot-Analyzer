/*
 * Dot Analyzer v8.0 — ImGui + OpenGL3 Edition
 *
 * Analyzes PGM images of dispensed fluid dots on a substrate.
 * Two measurement modes: Bounding Box and Body Detection (morphological).
 * Reports diameter, circularity, XY grid offset, and missed dots for every image.
 * Supports rectangular and staggered (hex) grid patterns.
 * Live preview with zoom/pan, grid overlay, crosshairs.
 * GVSP packet capture from Basler cameras (Npcap-based Record Mode).
 *
 * DEPENDENCIES:
 *   - ImGui (https://github.com/ocornut/imgui) with Win32 + OpenGL3 backends
 *   - Npcap (optional, for Record Mode)
 *
 * BUILD (MinGW-w64):
 *   g++ dot_analyzer_v8.cpp imgui/imgui.cpp imgui/imgui_draw.cpp ^
 *       imgui/imgui_tables.cpp imgui/imgui_widgets.cpp ^
 *       imgui/backends/imgui_impl_win32.cpp imgui/backends/imgui_impl_opengl3.cpp ^
 *       -o "Dot Analyzer.exe" -I./imgui -I./imgui/backends ^
 *       -lgdi32 -lopengl32 -ldwmapi -lcomdlg32 -lcomctl32 -lole32 ^
 *       -lshell32 -lshlwapi -lws2_32 -mwindows -O2 -DUNICODE -D_UNICODE
 */

/* ===== COMPILER & PLATFORM ===== */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define COBJMACROS

/* ===== SYSTEM HEADERS ===== */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <commctrl.h>
#include <GL/gl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <time.h>

#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((DPI_AWARENESS_CONTEXT)-4)
#endif

/* ===== IMGUI ===== */
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_opengl3.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "opengl32.lib")

/* ================================================================
 *  SECTION 1 — DYNAMIC NPCAP LOADING
 * ================================================================ */
typedef void pcap_t;
typedef unsigned int bpf_u_int32;
#define PCAP_ERRBUF_SIZE 256
#define PCAP_NETMASK_UNKNOWN 0xFFFFFFFF

struct pcap_pkthdr { struct timeval ts; unsigned int caplen; unsigned int len; };
struct bpf_program { unsigned int bf_len; void *bf_insns; };

struct pcap_addr {
    struct pcap_addr *next;
    struct sockaddr *addr, *netmask, *broadaddr, *dstaddr;
};
typedef struct pcap_if {
    struct pcap_if *next; char *name; char *description;
    struct pcap_addr *addresses; unsigned int flags;
} pcap_if_t;

typedef int    (*pfn_findalldevs)(pcap_if_t **, char *);
typedef void   (*pfn_freealldevs)(pcap_if_t *);
typedef pcap_t*(*pfn_open_live)(const char *, int, int, int, char *);
typedef int    (*pfn_next_ex)(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
typedef int    (*pfn_compile)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
typedef int    (*pfn_setfilter)(pcap_t *, struct bpf_program *);
typedef void   (*pfn_freecode)(struct bpf_program *);
typedef void   (*pfn_close)(pcap_t *);
typedef char  *(*pfn_geterr)(pcap_t *);

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

/* ================================================================
 *  SECTION 2 — CONSTANTS & DATA STRUCTURES
 * ================================================================ */
#define GVSP_HDR_SZ      8
#define GVSP_FMT_LEADER  0x01
#define GVSP_FMT_DATA    0x03
#define GVSP_FMT_TRAILER 0x02

#define REC_WIDTH   1280
#define REC_HEIGHT  1024
#define REC_FRAME_SZ (REC_WIDTH * REC_HEIGHT)

#define REC_IDLE        0
#define REC_DISCOVERING 1
#define REC_RECORDING   2
#define REC_STOPPING    3

#define MAX_BLOBS       4096
#define MAX_PATH_LEN    1024
#define MAX_FILES       2048
#define BORDER_PAD      2
#define FONT_W          5
#define FONT_H          7
#define MERGE_RATIO     1.85
#define PI              3.14159265358979323846
#define CONFIG_FILENAME L"dot_analyzer.cfg"

#define MODE_BBOX   0
#define MODE_BODY   1

#define GRIDPAT_RECT      0
#define GRIDPAT_STAGGERED 1

#define LEFT_PANEL_W  440
#define MIN_WIN_W     1060
#define MIN_WIN_H     720

#define WM_REC_STATUS (WM_APP + 100)
#define WM_REC_SAVED  (WM_APP + 101)

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

/* ================================================================
 *  SECTION 3 — APPLICATION STATE (replaces scattered Win32 globals)
 * ================================================================ */
static HWND  g_hwnd;
static HINSTANCE g_hinst;

/* Analysis parameters */
static char   g_folder_a[MAX_PATH_LEN] = "";
static wchar_t g_folder_w[MAX_PATH_LEN] = L"";
static char   g_pxmm_buf[64]   = "10.0";
static int    g_mode            = MODE_BBOX;
static int    g_auto_thresh     = 1;
static int    g_threshold       = 100;
static int    g_min_area        = 150;
static int    g_erosion         = 4;
static int    g_show_cross      = 0;
static int    g_show_grid       = 0;
static int    g_grid_pattern    = GRIDPAT_RECT;

/* Preview */
static pgm_image_t g_preview_img = {0};
static uint8_t    *g_preview_rgb = NULL;
static int         g_preview_valid = 0;
static int         g_preview_index = 0, g_preview_nfiles = 0;
static char        g_preview_files[MAX_FILES][MAX_PATH_LEN];
static blob_t      g_preview_blobs[MAX_BLOBS];
static int         g_preview_nblobs = 0;
static grid_params_t g_preview_gp = {0};
static int         g_preview_min_area_detected = 0;
static int         g_preview_missed_dots = 0;
static char        g_preview_info[384] = "";
static char        g_imgnum_label[320] = "No images";

/* Zoom */
static int    g_zoom_active = 0;
static double g_zoom = 1.0;
static double g_pan_x = 0.0, g_pan_y = 0.0;
static int    g_dragging = 0;
static int    g_drag_mx, g_drag_my;
static double g_drag_px, g_drag_py;

/* Preview dirty flag (set when params change, triggers rebuild) */
static int    g_preview_dirty = 1;

/* The screen-space rectangle where the preview is drawn (set during Nuklear layout) */
static struct { float x, y, w, h; } g_preview_rect = {0, 0, 100, 100};

/* Status / progress */
static char   g_status_text[1024] = "Ready. Select a folder and configure settings.";
static int    g_progress_val = 0, g_progress_max = 0;
static int    g_processing = 0;

/* Record Mode */
#define MAX_IFACES 32
static char  g_iface_names[MAX_IFACES][512];
static char  g_iface_descs[MAX_IFACES][256];
static int   g_iface_count = 0;
static int   g_iface_sel   = 0;
static char  g_outfolder_a[MAX_PATH_LEN] = "";
static wchar_t g_outfolder_w[MAX_PATH_LEN] = L"";
static char  g_stable_sec_buf[32] = "0.25";
static char  g_mad_thresh_buf[32] = "12";
static int   g_rec_state = REC_IDLE;
static HANDLE g_rec_thread = NULL;
static CRITICAL_SECTION g_rec_cs;
static volatile int g_rec_stop = 0;
static int   g_rec_save_count = 0;
static char  g_rec_iface[512];
static char  g_rec_outdir[MAX_PATH_LEN];
static double g_rec_stable_sec;
static double g_rec_mad_thresh;
static char  g_rec_status[512] = "Record: idle";

/* ================================================================
 *  SECTION 4 — RECORDING THREAD (preserved from v7.3)
 * ================================================================ */
static void rec_set_status(const wchar_t *msg) {
    WideCharToMultiByte(CP_UTF8, 0, msg, -1, g_rec_status, sizeof(g_rec_status), NULL, NULL);
}

static void rec_notify_saved(int count) {
    PostMessageW(g_hwnd, WM_REC_SAVED, (WPARAM)count, 0);
}

static double compute_mad(const uint8_t *a, const uint8_t *b, uint32_t size) {
    long long total = 0; uint32_t samples = 0;
    for (uint32_t i = 0; i < size; i += 4) {
        int d = (int)a[i] - (int)b[i];
        total += (d < 0) ? -d : d; samples++;
    }
    return (double)total / samples;
}

static DWORD WINAPI recording_thread(LPVOID param) {
    (void)param;
    char errbuf[PCAP_ERRBUF_SIZE];

    rec_set_status(L"Opening interface...");
    pcap_t *handle = p_open_live(g_rec_iface, 65535, 1, 10, errbuf);
    if (!handle) {
        wchar_t msg[512]; swprintf(msg, 512, L"Cannot open interface: %hs", errbuf);
        rec_set_status(msg);
        EnterCriticalSection(&g_rec_cs); g_rec_state = REC_IDLE; LeaveCriticalSection(&g_rec_cs);
        return 1;
    }

    rec_set_status(L"Discovering camera stream (ensure MYD is streaming)...");

    char discovered_ip[64] = ""; uint16_t discovered_port = 0; int found = 0;
    time_t disc_start = time(NULL);

    while (!found && !g_rec_stop && (time(NULL) - disc_start < 15)) {
        struct pcap_pkthdr *hdr; const unsigned char *pkt;
        int res = p_next_ex(handle, &hdr, &pkt);
        if (res <= 0) continue; if (hdr->caplen < 50) continue;
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
            snprintf(discovered_ip, sizeof(discovered_ip), "%d.%d.%d.%d",
                     ip[12], ip[13], ip[14], ip[15]);
            discovered_port = (udp[2] << 8) | udp[3];
            int confirm = 0; time_t conf_start = time(NULL);
            while (confirm < 3 && !g_rec_stop && (time(NULL) - conf_start < 3)) {
                res = p_next_ex(handle, &hdr, &pkt);
                if (res <= 0) continue; if (hdr->caplen < 50) continue;
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

    { char filt[256];
      snprintf(filt, sizeof(filt), "udp and src host %s and dst port %d", discovered_ip, discovered_port);
      struct bpf_program fp;
      if (p_compile(handle, &fp, filt, 1, PCAP_NETMASK_UNKNOWN) == 0) {
          p_setfilter(handle, &fp); p_freecode(&fp); }
    }

    { wchar_t msg[256]; swprintf(msg, 256, L"Recording from %hs port %d \u2014 waiting for stable frames...",
            discovered_ip, discovered_port);
      rec_set_status(msg); }

    EnterCriticalSection(&g_rec_cs); g_rec_state = REC_RECORDING; LeaveCriticalSection(&g_rec_cs);

    uint8_t *frame_buf = (uint8_t *)malloc(REC_FRAME_SZ);
    uint8_t *prev_buf  = (uint8_t *)malloc(REC_FRAME_SZ);
    if (!frame_buf || !prev_buf) {
        free(frame_buf); free(prev_buf); p_close(handle);
        rec_set_status(L"Memory allocation failed");
        EnterCriticalSection(&g_rec_cs); g_rec_state=REC_IDLE; LeaveCriticalSection(&g_rec_cs);
        return 1;
    }

    uint32_t cursor = 0; uint16_t cur_block = 0;
    int have_prev = 0, stable_count = 0, stable_saved = 0;
    int save_count = 0, frames_seen = 0;
    int stable_frames_needed = (int)(g_rec_stable_sec * 60.0);
    if (stable_frames_needed < 2) stable_frames_needed = 2;
    double mad_threshold = g_rec_mad_thresh;
    int diag_counter = 0;

    while (!g_rec_stop) {
        struct pcap_pkthdr *hdr; const unsigned char *pkt;
        int res = p_next_ex(handle, &hdr, &pkt);
        if (res <= 0) continue; if (hdr->caplen < 50) continue;
        const unsigned char *ip = pkt + 14;
        if ((ip[0]>>4)!=4||ip[9]!=17) continue;
        int ihl=(ip[0]&0x0F)*4;
        const unsigned char *udp=ip+ihl;
        uint16_t udp_len=(udp[4]<<8)|udp[5];
        if (udp_len < 8+GVSP_HDR_SZ) continue;
        uint16_t payload_len = udp_len - 8;
        const unsigned char *gvsp = udp+8;
        uint8_t fmt = gvsp[4]; uint16_t blk = (gvsp[2]<<8)|gvsp[3];

        switch (fmt) {
        case GVSP_FMT_LEADER:
            cursor = 0; cur_block = blk; frames_seen++; break;
        case GVSP_FMT_DATA:
            if (blk != cur_block) break;
            { uint16_t dlen = payload_len - GVSP_HDR_SZ;
              const unsigned char *dptr = gvsp + GVSP_HDR_SZ;
              if (cursor + dlen <= (uint32_t)REC_FRAME_SZ) {
                  memcpy(&frame_buf[cursor], dptr, dlen); cursor += dlen;
              } else {
                  uint32_t space = REC_FRAME_SZ - cursor;
                  if (space > 0) { memcpy(&frame_buf[cursor], dptr, space); cursor = REC_FRAME_SZ; }
              }
            } break;
        case GVSP_FMT_TRAILER:
            if (cursor >= (uint32_t)REC_FRAME_SZ) {
                if (have_prev) {
                    double mad = compute_mad(frame_buf, prev_buf, REC_FRAME_SZ);
                    diag_counter++;
                    if (diag_counter % 60 == 0) {
                        wchar_t msg[256];
                        swprintf(msg, 256, L"MAD=%.1f (thresh=%.1f) | %d seen, %d saved | stable=%d/%d | %hs:%d",
                                 mad, mad_threshold, frames_seen, save_count,
                                 stable_count, stable_frames_needed, discovered_ip, discovered_port);
                        rec_set_status(msg);
                    }
                    if (mad < mad_threshold) {
                        stable_count++;
                        if (stable_count >= stable_frames_needed && !stable_saved) {
                            char fname[MAX_PATH_LEN];
                            snprintf(fname, sizeof(fname), "%s\\capture_%04d.pgm", g_rec_outdir, save_count);
                            FILE *fp = fopen(fname, "wb");
                            if (fp) {
                                uint8_t *flip_buf = (uint8_t *)malloc(REC_FRAME_SZ);
                                if (flip_buf) {
                                    for (int i = 0; i < REC_FRAME_SZ; i++)
                                        flip_buf[i] = frame_buf[REC_FRAME_SZ - 1 - i];
                                    fprintf(fp, "P5\n%d %d\n255\n", REC_WIDTH, REC_HEIGHT);
                                    fwrite(flip_buf, 1, REC_FRAME_SZ, fp); free(flip_buf);
                                } else {
                                    fprintf(fp, "P5\n%d %d\n255\n", REC_WIDTH, REC_HEIGHT);
                                    fwrite(frame_buf, 1, REC_FRAME_SZ, fp);
                                }
                                fclose(fp); save_count++; rec_notify_saved(save_count);
                                wchar_t msg[256];
                                swprintf(msg, 256, L"Saved capture_%04d.pgm (%d total) \u2014 stream %hs:%d",
                                         save_count - 1, save_count, discovered_ip, discovered_port);
                                rec_set_status(msg);
                            }
                            stable_saved = 1;
                        }
                    } else { stable_count = 0; stable_saved = 0; }
                }
                memcpy(prev_buf, frame_buf, REC_FRAME_SZ); have_prev = 1;
            } break;
        }
    }

    free(frame_buf); free(prev_buf); p_close(handle);
    { wchar_t msg[256]; swprintf(msg, 256, L"Stopped. Saved %d frames from %d seen.", save_count, frames_seen);
      rec_set_status(msg); }
    EnterCriticalSection(&g_rec_cs); g_rec_state = REC_IDLE; LeaveCriticalSection(&g_rec_cs);
    g_rec_save_count = save_count;
    return 0;
}

/* ================================================================
 *  SECTION 5 — PGM I/O (preserved)
 * ================================================================ */
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

/* ================================================================
 *  SECTION 6 — IMAGE PROCESSING (preserved)
 * ================================================================ */
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

/* ================================================================
 *  SECTION 7 — GRID INFERENCE (preserved verbatim)
 * ================================================================ */
static int cmp_double(const void *a,const void *b){
    double da=*(const double*)a,db=*(const double*)b;return(da>db)-(da<db);}
static double median_arr(double *a,int n){if(n<=0)return 0;
    qsort(a,n,sizeof(double),cmp_double);
    return(n%2==1)?a[n/2]:(a[n/2-1]+a[n/2])/2.0;}

static void infer_grid_params(const blob_t *blobs,int nblobs,grid_params_t *gp,int gridpat,int use_body,int img_w,int img_h){
    gp->valid=0;gp->staggered=0;gp->stagger_y=0;
    /* --- Robust centroid extraction with filtering --- */
    double *cxs=(double*)malloc(nblobs*sizeof(double));
    double *cys=(double*)malloc(nblobs*sizeof(double));
    if(!cxs||!cys){free(cxs);free(cys);return;}

    /* Compute median area and diameter of non-merged blobs */
    double *tmp=(double*)malloc(nblobs*sizeof(double));
    if(!tmp){free(cxs);free(cys);return;}
    int ntmp=0;
    for(int i=0;i<nblobs;i++) if(!blobs[i].merged) tmp[ntmp++]=(double)blobs[i].area;
    if(ntmp<4){free(cxs);free(cys);free(tmp);return;}
    double med_area=median_arr(tmp,ntmp);
    ntmp=0;
    for(int i=0;i<nblobs;i++) if(!blobs[i].merged) tmp[ntmp++]=(double)blobs[i].diameter_px;
    double med_diam=median_arr(tmp,ntmp);
    free(tmp);

    double edge_margin=med_diam*0.5; if(edge_margin<10) edge_margin=10;
    double area_lo=med_area*0.25, area_hi=med_area*3.0;

    int nc=0;
    for(int i=0;i<nblobs;i++){
        if(blobs[i].merged) continue;
        if(blobs[i].area<area_lo||blobs[i].area>area_hi) continue;
        double cx,cy;
        if(use_body&&blobs[i].body_area>0){cx=blobs[i].body_cx;cy=blobs[i].body_cy;}
        else{cx=(double)blobs[i].cx;cy=(double)blobs[i].cy;}
        if(cx<edge_margin||cx>img_w-edge_margin||cy<edge_margin||cy>img_h-edge_margin) continue;
        cxs[nc]=cx;cys[nc]=cy;nc++;
    }
    if(nc<4){free(cxs);free(cys);return;}
    double *nn_d=(double*)malloc(nc*sizeof(double));
    if(!nn_d){free(cxs);free(cys);return;}
    for(int i=0;i<nc;i++){double best=1e18;for(int j=0;j<nc;j++){if(i==j)continue;
        double d=(cxs[i]-cxs[j])*(cxs[i]-cxs[j])+(cys[i]-cys[j])*(cys[i]-cys[j]);
        if(d<best)best=d;}nn_d[i]=sqrt(best);}
    double med_nn=median_arr(nn_d,nc);free(nn_d);
    int *si2=(int*)malloc(nc*sizeof(int));if(!si2){free(cxs);free(cys);return;}
    for(int i=0;i<nc;i++) si2[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(cys[si2[j]]<cys[si2[i]]){int t=si2[i];si2[i]=si2[j];si2[j]=t;}
    double gap_th=med_nn*0.5;
    int *rs=(int*)calloc(nc,sizeof(int)),*rcnt=(int*)calloc(nc,sizeof(int));
    if(!rs||!rcnt){free(cxs);free(cys);free(si2);free(rs);free(rcnt);return;}
    int nrows=1;rs[0]=0;rcnt[0]=1;
    for(int i=1;i<nc;i++){
        if(cys[si2[i]]-cys[si2[i-1]]>gap_th){nrows++;rs[nrows-1]=i;rcnt[nrows-1]=1;}
        else rcnt[nrows-1]++;}
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
    double ca=cos(-angle),sna=sin(-angle);
    double *rxs=(double*)malloc(nc*sizeof(double)),*rys=(double*)malloc(nc*sizeof(double));
    if(!rxs||!rys){free(cxs);free(cys);free(si2);free(rs);free(rcnt);free(rxs);free(rys);return;}
    for(int i=0;i<nc;i++){rxs[i]=cxs[i]*ca-cys[i]*sna;rys[i]=cxs[i]*sna+cys[i]*ca;}
    for(int i=0;i<nc;i++) si2[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(rys[si2[j]]<rys[si2[i]]){int t=si2[i];si2[i]=si2[j];si2[j]=t;}
    int nr2=1;rs[0]=0;rcnt[0]=1;
    for(int i=1;i<nc;i++){
        if(rys[si2[i]]-rys[si2[i-1]]>gap_th){nr2++;rs[nr2-1]=i;rcnt[nr2-1]=1;}
        else rcnt[nr2-1]++;}
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
    double *rmy=(double*)malloc(nr2*sizeof(double));int nrmy=0;
    double *rmx=(double*)malloc(nr2*sizeof(double));
    int *rmi=(int*)calloc(nr2,sizeof(int));
    if(rmy&&rmx&&rmi){for(int r=0;r<nr2;r++){if(rcnt[r]<2){rmx[r]=0;continue;}
        double sx2=0,sy2=0;for(int k=0;k<rcnt[r];k++){
            sx2+=rxs[si2[rs[r]+k]];sy2+=rys[si2[rs[r]+k]];}
        rmx[nrmy]=sx2/rcnt[r];rmy[nrmy]=sy2/rcnt[r];rmi[nrmy]=r;nrmy++;}
    for(int i=0;i<nrmy-1;i++) for(int j=i+1;j<nrmy;j++)
        if(rmy[j]<rmy[i]){double t=rmy[i];rmy[i]=rmy[j];rmy[j]=t;
            t=rmx[i];rmx[i]=rmx[j];rmx[j]=t;
            int ti=rmi[i];rmi[i]=rmi[j];rmi[j]=ti;}
    for(int i=0;i<nrmy-1;i++){double d=rmy[i+1]-rmy[i];
        if(d>med_nn*0.6&&d<med_nn*1.5&&nys<mxs) ysps[nys++]=d;}}
    if(nxs<2||nys<2){free(cxs);free(cys);free(si2);free(rs);free(rcnt);
        free(rxs);free(rys);free(xsps);free(ysps);free(rmy);free(rmx);free(rmi);return;}
    gp->spacing_x=median_arr(xsps,nxs);gp->spacing_y=median_arr(ysps,nys);
    if(gridpat==GRIDPAT_STAGGERED && nrmy>=3 && gp->spacing_x>1.0){
        int stag_votes=0,nstag=0;
        for(int i=0;i<nrmy;i++){
            int r=rmi[i]; int rstart2=rs[r],cnt=rcnt[r];
            double min_rx=1e18;
            for(int k=0;k<cnt;k++){double x=rxs[si2[rstart2+k]];if(x<min_rx)min_rx=x;}
            if(i>0){
                int r0=rmi[0]; int rs0=rs[r0],cnt0=rcnt[r0];
                double min_rx0=1e18;
                for(int k=0;k<cnt0;k++){double x=rxs[si2[rs0+k]];if(x<min_rx0)min_rx0=x;}
                double delta=fmod(fabs(min_rx-min_rx0), gp->spacing_x);
                if(delta>gp->spacing_x/2) delta=gp->spacing_x-delta;
                nstag++;
                if(fabs(delta-gp->spacing_x/2.0)<gp->spacing_x*0.25) stag_votes++;
            }
        }
        if(nstag>0 && stag_votes*2>=nstag) gp->staggered=1;
    }
    if(gridpat==GRIDPAT_STAGGERED) gp->staggered=1;
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

/* Checker / staggered grid inference (column-first) */
static void infer_grid_params_checker(const blob_t *blobs,int nblobs,grid_params_t *gp,int use_body,int img_w,int img_h){
    gp->valid=0;gp->staggered=0;gp->stagger_y=0;
    double *cxs=(double*)malloc(nblobs*sizeof(double));
    double *cys=(double*)malloc(nblobs*sizeof(double));
    if(!cxs||!cys){free(cxs);free(cys);return;}

    /* Compute median area and diameter of non-merged blobs */
    double *tmp=(double*)malloc(nblobs*sizeof(double));
    if(!tmp){free(cxs);free(cys);return;}
    int ntmp=0;
    for(int i=0;i<nblobs;i++) if(!blobs[i].merged) tmp[ntmp++]=(double)blobs[i].area;
    if(ntmp<4){free(cxs);free(cys);free(tmp);return;}
    double med_area=median_arr(tmp,ntmp);
    ntmp=0;
    for(int i=0;i<nblobs;i++) if(!blobs[i].merged) tmp[ntmp++]=(double)blobs[i].diameter_px;
    double med_diam=median_arr(tmp,ntmp);
    free(tmp);

    double edge_margin=med_diam*0.5; if(edge_margin<10) edge_margin=10;
    double area_lo=med_area*0.25, area_hi=med_area*3.0;

    int nc=0;
    for(int i=0;i<nblobs;i++){
        if(blobs[i].merged) continue;
        if(blobs[i].area<area_lo||blobs[i].area>area_hi) continue;
        double cx,cy;
        if(use_body&&blobs[i].body_area>0){cx=blobs[i].body_cx;cy=blobs[i].body_cy;}
        else{cx=(double)blobs[i].cx;cy=(double)blobs[i].cy;}
        if(cx<edge_margin||cx>img_w-edge_margin||cy<edge_margin||cy>img_h-edge_margin) continue;
        cxs[nc]=cx;cys[nc]=cy;nc++;
    }
    if(nc<4){free(cxs);free(cys);return;}
    double *nn_d=(double*)malloc(nc*sizeof(double));
    if(!nn_d){free(cxs);free(cys);return;}
    for(int i=0;i<nc;i++){double best=1e18;for(int j=0;j<nc;j++){if(i==j)continue;
        double d=(cxs[i]-cxs[j])*(cxs[i]-cxs[j])+(cys[i]-cys[j])*(cys[i]-cys[j]);
        if(d<best)best=d;}nn_d[i]=sqrt(best);}
    double med_nn=median_arr(nn_d,nc);free(nn_d);
    int *si_x=(int*)malloc(nc*sizeof(int));if(!si_x){free(cxs);free(cys);return;}
    for(int i=0;i<nc;i++) si_x[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(cxs[si_x[j]]<cxs[si_x[i]]){int t=si_x[i];si_x[i]=si_x[j];si_x[j]=t;}
    double col_gap_th=med_nn*0.4;
    int max_cols=nc;
    int *col_start=(int*)calloc(max_cols,sizeof(int));
    int *col_count=(int*)calloc(max_cols,sizeof(int));
    if(!col_start||!col_count){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);return;}
    int ncols=1;col_start[0]=0;col_count[0]=1;
    for(int i=1;i<nc;i++){
        if(cxs[si_x[i]]-cxs[si_x[i-1]]>col_gap_th){ncols++;col_start[ncols-1]=i;col_count[ncols-1]=1;}
        else col_count[ncols-1]++;}
    int *si_y=(int*)malloc(nc*sizeof(int));
    if(!si_y){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);return;}
    for(int i=0;i<nc;i++) si_y[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(cys[si_y[j]]<cys[si_y[i]]){int t=si_y[i];si_y[i]=si_y[j];si_y[j]=t;}
    double row_gap_th=med_nn*0.35;
    int *row_start=(int*)calloc(nc,sizeof(int)),*row_count=(int*)calloc(nc,sizeof(int));
    if(!row_start||!row_count){free(cxs);free(cys);free(si_x);free(si_y);
        free(col_start);free(col_count);free(row_start);free(row_count);return;}
    int nrows=1;row_start[0]=0;row_count[0]=1;
    for(int i=1;i<nc;i++){
        if(cys[si_y[i]]-cys[si_y[i-1]]>row_gap_th){nrows++;row_start[nrows-1]=i;row_count[nrows-1]=1;}
        else row_count[nrows-1]++;}
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
    double ca=cos(-angle),sna=sin(-angle);
    double *rxs=(double*)malloc(nc*sizeof(double)),*rys=(double*)malloc(nc*sizeof(double));
    if(!rxs||!rys){free(cxs);free(cys);free(si_x);free(col_start);free(col_count);free(rxs);free(rys);return;}
    for(int i=0;i<nc;i++){rxs[i]=cxs[i]*ca-cys[i]*sna;rys[i]=cxs[i]*sna+cys[i]*ca;}
    for(int i=0;i<nc;i++) si_x[i]=i;
    for(int i=0;i<nc-1;i++) for(int j=i+1;j<nc;j++)
        if(rxs[si_x[j]]<rxs[si_x[i]]){int t=si_x[i];si_x[i]=si_x[j];si_x[j]=t;}
    ncols=1;col_start[0]=0;col_count[0]=1;
    for(int i=1;i<nc;i++){
        if(rxs[si_x[i]]-rxs[si_x[i-1]]>col_gap_th){ncols++;col_start[ncols-1]=i;col_count[ncols-1]=1;}
        else col_count[ncols-1]++;}
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
    for(int c=0;c<ncols-1;c++){
        double d=col_mx[c+1]-col_mx[c];
        if(d>med_nn*0.6&&d<med_nn*1.5&&ndx<max_sp) dxs[ndx++]=d;
    }
    for(int c=0;c<ncols;c++){
        if(col_count[c]<2) continue;
        int cs=col_start[c],cnt=col_count[c];
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

    /* --- Phase-clustering stagger detection ---
     * Instead of relying on column index parity (c%2), which breaks when
     * spurious debris "columns" shift the index, we:
     *   1. Compute y-phase for every column with >=3 dots
     *   2. Use the most-populous column as the phase reference
     *   3. Cluster all columns into two groups by phase proximity
     *   4. Derive stagger_y from the two cluster centers
     * This is immune to phantom columns from debris. */

    int min_col_dots=3;  /* require >=3 dots per column to trust its phase */
    double *col_phases=(double*)malloc(ncols*sizeof(double));
    int    *col_phase_valid=(int*)calloc(ncols,sizeof(int));
    int    *col_phase_cnt=(int*)calloc(ncols,sizeof(int)); /* dot count for weighting */
    int nphase_cols=0;
    if(col_phases&&col_phase_valid&&col_phase_cnt){
        for(int c=0;c<ncols;c++){
            if(col_count[c]<min_col_dots) continue;
            int cs=col_start[c],cnt=col_count[c];
            double sin_sum=0,cos_sum=0;
            for(int k=0;k<cnt;k++){
                double y=rys[si_x[cs+k]];
                double r=fmod(y,gp->spacing_y);if(r<0)r+=gp->spacing_y;
                double ang=2.0*PI*r/gp->spacing_y;
                sin_sum+=sin(ang);cos_sum+=cos(ang);
            }
            double phase=atan2(sin_sum,cos_sum)*gp->spacing_y/(2.0*PI);
            if(phase<0)phase+=gp->spacing_y;
            col_phases[c]=phase;
            col_phase_valid[c]=1;
            col_phase_cnt[c]=cnt;
            nphase_cols++;
        }
    }

    /* Find reference column = most populous valid column */
    int ref_col=-1; int ref_cnt=0;
    for(int c=0;c<ncols;c++){
        if(!col_phase_valid[c]) continue;
        if(col_phase_cnt[c]>ref_cnt){ref_cnt=col_phase_cnt[c];ref_col=c;}
    }

    double stagger_y=0;
    double ref_phase=0; int have_ref_phase=0;
    int ref_col_anchor=-1; /* which column index anchors our origin (group A) */

    if(ref_col>=0 && nphase_cols>=2){
        ref_phase=col_phases[ref_col]; have_ref_phase=1;
        ref_col_anchor=ref_col;

        /* Compute wrapped phase difference from reference for each column */
        double *diffs=(double*)malloc(ncols*sizeof(double));
        int *group=(int*)calloc(ncols,sizeof(int)); /* 0=A (same as ref), 1=B */
        int nA=0,nB=0;
        double sy2=gp->spacing_y;
        if(diffs&&group){
            for(int c=0;c<ncols;c++){
                if(!col_phase_valid[c]){group[c]=-1;continue;}
                double d=col_phases[c]-ref_phase;
                /* wrap to [-sy/2, sy/2] */
                while(d> sy2/2.0) d-=sy2;
                while(d<-sy2/2.0) d+=sy2;
                diffs[c]=d;
                if(fabs(d)<sy2/4.0){group[c]=0;nA++;}
                else{group[c]=1;nB++;}
            }
            if(nA>=1&&nB>=1){
                /* Compute median diff for group B = stagger offset */
                double *b_diffs=(double*)malloc(nB*sizeof(double));
                if(b_diffs){
                    int nb=0;
                    for(int c=0;c<ncols;c++)
                        if(group[c]==1) b_diffs[nb++]=diffs[c];
                    stagger_y=median_arr(b_diffs,nb);
                    if(fabs(stagger_y)>sy2*0.10){
                        gp->staggered=1; gp->stagger_y=stagger_y;
                    }
                    free(b_diffs);
                }
            }
        }
        free(diffs);free(group);
    } else if(ref_col>=0){
        ref_phase=col_phases[ref_col]; have_ref_phase=1;
        ref_col_anchor=ref_col;
    }
    free(col_phases);free(col_phase_valid);free(col_phase_cnt);

    double sx=gp->spacing_x,sy=gp->spacing_y;
    /* Anchor origin x to the reference column so that col==0 in the
       refinement loop maps to a group-A column, keeping stagger parity
       consistent with how stagger_y was measured. */
    double ox=(ref_col_anchor>=0) ? col_mx[ref_col_anchor] : col_mx[0];
    double oy=have_ref_phase ? ref_phase : rys[si_x[col_start[0]]];
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
            int col=(int)round((rx-ox)/sx);
            double col_oy=oy; if(col&1) col_oy=oy+gp->stagger_y;
            int row=(int)round((ry-col_oy)/sy);
            erx=rx-(ox+col*sx);
            ery=ry-(col_oy+row*sy);
            blobs[i].grid_col=col;blobs[i].grid_row=row;
        }else if(gp->staggered){
            int row=(int)round((ry-oy)/sy);
            double row_ox=ox; if(row&1) row_ox=ox+sx/2.0;
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

static int count_missed_dots(const blob_t *blobs,int nblobs,const grid_params_t *gp,
    int img_w,int img_h){
    if(!gp->valid||nblobs<2) return 0;
    double sx=gp->spacing_x,sy=gp->spacing_y;
    double ox=gp->origin_x,oy=gp->origin_y;
    double rca=cos(gp->angle),rsa=sin(gp->angle);
    int min_row=999999,max_row=-999999,min_col=999999,max_col=-999999;
    for(int i=0;i<nblobs;i++){
        if(blobs[i].merged||!blobs[i].grid_valid) continue;
        if(blobs[i].grid_row<min_row) min_row=blobs[i].grid_row;
        if(blobs[i].grid_row>max_row) max_row=blobs[i].grid_row;
        if(blobs[i].grid_col<min_col) min_col=blobs[i].grid_col;
        if(blobs[i].grid_col>max_col) max_col=blobs[i].grid_col;
    }
    if(min_row>max_row) return 0;
    int nr=max_row-min_row+1, nc=max_col-min_col+1;
    if(nr<=0||nc<=0||nr>500||nc>500) return 0;
    uint8_t *occupied=(uint8_t*)calloc(nr*nc,1);
    if(!occupied) return 0;
    for(int i=0;i<nblobs;i++){
        if(blobs[i].merged||!blobs[i].grid_valid) continue;
        int r=blobs[i].grid_row-min_row, c=blobs[i].grid_col-min_col;
        if(r>=0&&r<nr&&c>=0&&c<nc) occupied[r*nc+c]=1;
    }
    int missed=0;
    double margin=sx*0.3;
    int use_stagger_y=(gp->staggered && fabs(gp->stagger_y)>0.01);
    for(int r=0;r<nr;r++){
        int row=r+min_row;
        for(int c=0;c<nc;c++){
            int col=c+min_col;
            if(occupied[r*nc+c]) continue;
            double rx,ry;
            if(use_stagger_y){
                rx=ox+col*sx;
                double col_oy=oy; if(col&1) col_oy=oy+gp->stagger_y;
                ry=col_oy+row*sy;
            }else{
                double row_ox=ox;
                if(gp->staggered && (row&1)) row_ox=ox+sx/2.0;
                rx=row_ox+col*sx; ry=oy+row*sy;
            }
            double ix=rx*rca-ry*rsa, iy=rx*rsa+ry*rca;
            if(ix>=margin && ix<img_w-margin && iy>=margin && iy<img_h-margin)
                missed++;
        }
    }
    free(occupied);
    return missed;
}

/* ================================================================
 *  SECTION 8 — ANNOTATION FONT & FILE ENUM (preserved)
 * ================================================================ */
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
    if(c>='0'&&c<='9') return c-'0';
    switch(c){case '.':return 10;case '-':return 11;case 'm':return 12;
    case ' ':return 13;case 'M':return 14;case 'E':return 15;
    case 'R':return 16;case 'G':return 17;case 'D':return 18;default:return 13;}
}
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

/* ================================================================
 *  SECTION 9 — STATISTICS (preserved)
 * ================================================================ */
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

/* ================================================================
 *  SECTION 10 — RGB PREVIEW RENDERING (adapted, no Win32 HWND deps)
 * ================================================================ */
static void rgb_px(uint8_t *rgb,int w,int h,int x,int y,uint8_t r,uint8_t g,uint8_t b){
    if(x>=0&&x<w&&y>=0&&y<h){int i=(y*w+x)*3;rgb[i]=b;rgb[i+1]=g;rgb[i+2]=r;}}

static void rgb_cross(uint8_t *rgb,int w,int h,int cx,int cy,double f,int sz){
    if(f<0)f=0;if(f>1)f=1;
    uint8_t r=(uint8_t)(255*f),g=(uint8_t)(255*(1-f)),b=0;
    for(int d=-sz;d<=sz;d++){rgb_px(rgb,w,h,cx+d,cy,r,g,b);rgb_px(rgb,w,h,cx,cy+d,r,g,b);}}

static void rgb_dash(uint8_t *rgb,int w,int h,int x0,int y0,int x1,int y1,
    uint8_t r,uint8_t g,uint8_t b,int dash_on,int dash_off){
    int dx2=abs(x1-x0),dy2=abs(y1-y0);
    int sx2=x0<x1?1:-1,sy2=y0<y1?1:-1;
    int err=dx2-dy2,step=0,total=dash_on+dash_off;
    for(;;){
        if(step%total<dash_on) rgb_px(rgb,w,h,x0,y0,r,g,b);
        if(x0==x1&&y0==y1)break;
        int e2=2*err;if(e2>-dy2){err-=dy2;x0+=sx2;}if(e2<dx2){err+=dx2;y0+=sy2;}step++;}}

static void build_preview_rgb(void) {
    if (!g_preview_img.pixels || !g_preview_rgb) return;
    int w = g_preview_img.width, h = g_preview_img.height;
    int thresh = g_threshold;
    if (g_auto_thresh && g_preview_img.pixels)
        thresh = compute_otsu(g_preview_img.pixels, w * h);
    g_threshold = thresh; /* keep in sync for display */

    int min_area = g_min_area, erosion_r = g_erosion, mode = g_mode;
    int need_full = (mode == MODE_BODY || g_show_cross || g_show_grid);

    /* Gray -> BGR */
    for (int i = 0; i < w*h; i++) {
        uint8_t v = g_preview_img.pixels[i];
        g_preview_rgb[i*3] = v; g_preview_rgb[i*3+1] = v; g_preview_rgb[i*3+2] = v;
    }

    /* Analysis */
    if (need_full)
        g_preview_nblobs = process_image_full(&g_preview_img, thresh, min_area, erosion_r,
            g_preview_blobs, MAX_BLOBS);
    else
        g_preview_nblobs = process_image_light(&g_preview_img, thresh, min_area,
            g_preview_blobs, MAX_BLOBS);

    /* Grid inference */
    g_preview_gp.valid = 0;
    g_preview_missed_dots = 0;
    if (g_show_cross || g_show_grid) {
        int use_body = (mode == MODE_BODY);
        if (g_grid_pattern == GRIDPAT_STAGGERED)
            infer_grid_params_checker(g_preview_blobs, g_preview_nblobs, &g_preview_gp, use_body, w, h);
        else
            infer_grid_params(g_preview_blobs, g_preview_nblobs, &g_preview_gp, g_grid_pattern, use_body, w, h);
        if (g_preview_gp.valid) {
            compute_grid_offsets(g_preview_blobs, g_preview_nblobs, &g_preview_gp, 10.0, mode == MODE_BODY);
            g_preview_missed_dots = count_missed_dots(g_preview_blobs, g_preview_nblobs, &g_preview_gp, w, h);
        }
    }

    /* Min detected area */
    g_preview_min_area_detected = 0;
    if (g_preview_nblobs > 0) {
        int mn = 0x7FFFFFFF;
        for (int i = 0; i < g_preview_nblobs; i++)
            if (g_preview_blobs[i].area < mn) mn = g_preview_blobs[i].area;
        g_preview_min_area_detected = mn;
    }

    /* Draw grid lines */
    if (g_show_grid && g_preview_gp.valid) {
        double a=g_preview_gp.angle,sx=g_preview_gp.spacing_x,sy=g_preview_gp.spacing_y;
        double ox=g_preview_gp.origin_x,oy=g_preview_gp.origin_y;
        double ca2=cos(-a),sa2=sin(-a);
        int use_stagger_y=(g_preview_gp.staggered && fabs(g_preview_gp.stagger_y)>0.01);
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
            for(int col=min_col;col<=max_col;col++){
                double rx2=ox+col*sx;
                double ry0=rmin_y-sy,ry1=rmax_y+sy;
                int ix0=(int)(rx2*rca-ry0*rsa),iy0=(int)(rx2*rsa+ry0*rca);
                int ix1=(int)(rx2*rca-ry1*rsa),iy1=(int)(rx2*rsa+ry1*rca);
                rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,6,4);}
            double tick_half=sx*0.45;
            for(int col=min_col;col<=max_col;col++){
                double col_oy=oy; if(col&1) col_oy=oy+g_preview_gp.stagger_y;
                double rx_c=ox+col*sx;
                for(int row=min_row;row<=max_row;row++){
                    double ry2=col_oy+row*sy;
                    double rx0=rx_c-tick_half,rx1=rx_c+tick_half;
                    int ix0=(int)(rx0*rca-ry2*rsa),iy0=(int)(rx0*rsa+ry2*rca);
                    int ix1=(int)(rx1*rca-ry2*rsa),iy1=(int)(rx1*rsa+ry2*rca);
                    rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,4,4);}}
        }else{
            for(int row=min_row;row<=max_row;row++){
                double ry=oy+row*sy;
                double rx0=rmin_x-sx,rx1=rmax_x+sx;
                int ix0=(int)(rx0*rca-ry*rsa),iy0=(int)(rx0*rsa+ry*rca);
                int ix1=(int)(rx1*rca-ry*rsa),iy1=(int)(rx1*rsa+ry*rca);
                rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,6,4);}
            if(g_preview_gp.staggered){
                for(int row=min_row;row<=max_row;row++){
                    double ry=oy+row*sy; double row_ox=ox;
                    if(row&1) row_ox=ox+sx/2.0;
                    for(int col=min_col;col<=max_col;col++){
                        double rx2=row_ox+col*sx;
                        double ry0=ry-sy*0.5,ry1=ry+sy*0.5;
                        int ix0=(int)(rx2*rca-ry0*rsa),iy0=(int)(rx2*rsa+ry0*rca);
                        int ix1=(int)(rx2*rca-ry1*rsa),iy1=(int)(rx2*rsa+ry1*rca);
                        rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,4,4);}}
            }else{
                for(int col=min_col;col<=max_col;col++){
                    double rx2=ox+col*sx;
                    double ry0=rmin_y-sy,ry1=rmax_y+sy;
                    int ix0=(int)(rx2*rca-ry0*rsa),iy0=(int)(rx2*rsa+ry0*rca);
                    int ix1=(int)(rx2*rca-ry1*rsa),iy1=(int)(rx2*rsa+ry1*rca);
                    rgb_dash(g_preview_rgb,w,h,ix0,iy0,ix1,iy1,30,70,180,6,4);}}
        }
        /* Missed dot markers */
        if(g_preview_missed_dots>0&&g_preview_nblobs>1){
            int gmin_r=999999,gmax_r=-999999,gmin_c=999999,gmax_c=-999999;
            for(int bi=0;bi<g_preview_nblobs;bi++){
                blob_t *b2=&g_preview_blobs[bi];
                if(b2->merged||!b2->grid_valid)continue;
                if(b2->grid_row<gmin_r)gmin_r=b2->grid_row;if(b2->grid_row>gmax_r)gmax_r=b2->grid_row;
                if(b2->grid_col<gmin_c)gmin_c=b2->grid_col;if(b2->grid_col>gmax_c)gmax_c=b2->grid_col;}
            int gnr=gmax_r-gmin_r+1,gnc=gmax_c-gmin_c+1;
            if(gnr>0&&gnc>0&&gnr<=500&&gnc<=500){
                uint8_t *occ=(uint8_t*)calloc(gnr*gnc,1);
                if(occ){
                    for(int bi=0;bi<g_preview_nblobs;bi++){
                        blob_t *b2=&g_preview_blobs[bi];
                        if(b2->merged||!b2->grid_valid)continue;
                        int rr=b2->grid_row-gmin_r,cc=b2->grid_col-gmin_c;
                        if(rr>=0&&rr<gnr&&cc>=0&&cc<gnc)occ[rr*gnc+cc]=1;}
                    double margin=sx*0.3;
                    int use_stagger_y2=(g_preview_gp.staggered && fabs(g_preview_gp.stagger_y)>0.01);
                    for(int rr=0;rr<gnr;rr++)for(int cc=0;cc<gnc;cc++){
                        if(occ[rr*gnc+cc])continue;
                        int row=rr+gmin_r,col=cc+gmin_c;
                        double rrx,rry;
                        if(use_stagger_y2){
                            rrx=ox+col*sx;
                            double col_oy2=oy; if(col&1) col_oy2=oy+g_preview_gp.stagger_y;
                            rry=col_oy2+row*sy;
                        }else{
                            double row_ox2=ox;
                            if(g_preview_gp.staggered&&(row&1))row_ox2=ox+sx/2.0;
                            rrx=row_ox2+col*sx;rry=oy+row*sy;}
                        double ix2=rrx*rca-rry*rsa,iy2=rrx*rsa+rry*rca;
                        if(ix2>=margin&&ix2<w-margin&&iy2>=margin&&iy2<h-margin){
                            int cix=(int)ix2,ciy=(int)iy2,rad=6;
                            for(int da=0;da<360;da+=5){
                                double ar=da*PI/180.0;
                                int px=(int)(cix+rad*cos(ar)),py=(int)(ciy+rad*sin(ar));
                                rgb_px(g_preview_rgb,w,h,px,py,255,0,0);}
                            for(int dd=-4;dd<=4;dd++){
                                rgb_px(g_preview_rgb,w,h,cix+dd,ciy+dd,255,0,0);
                                rgb_px(g_preview_rgb,w,h,cix+dd,ciy-dd,255,0,0);}
                        }
                    }
                    free(occ);
                }
            }
        }
    }

    /* Bounding boxes */
    for (int bi = 0; bi < g_preview_nblobs; bi++) {
        blob_t *b = &g_preview_blobs[bi];
        int bx0, by0, bx1, by1;
        if (mode == MODE_BODY && need_full) {
            bx0=b->body_min_x-BORDER_PAD; by0=b->body_min_y-BORDER_PAD;
            bx1=b->body_max_x+BORDER_PAD; by1=b->body_max_y+BORDER_PAD;
        } else {
            bx0=b->min_x-BORDER_PAD; by0=b->min_y-BORDER_PAD;
            bx1=b->max_x+BORDER_PAD; by1=b->max_y+BORDER_PAD;
        }
        if(bx0<0)bx0=0;if(by0<0)by0=0;if(bx1>=w)bx1=w-1;if(by1>=h)by1=h-1;
        uint8_t cr=b->merged?255:0,cg=b->merged?0:255,cb=0;
        for(int x=bx0;x<=bx1;x++)for(int t=0;t<2;t++){
            int yy=(t==0)?by0+t:by1-t+1;if(yy>=0&&yy<h)rgb_px(g_preview_rgb,w,h,x,yy,cr,cg,cb);}
        for(int y=by0;y<=by1;y++)for(int t=0;t<2;t++){
            int xx=(t==0)?bx0+t:bx1-t+1;if(xx>=0&&xx<w)rgb_px(g_preview_rgb,w,h,xx,y,cr,cg,cb);}
    }

    /* Crosshairs */
    if (g_show_cross) {
        double max_off = g_preview_gp.valid ? (g_preview_gp.spacing_x * 0.25) : 20.0;
        if (max_off < 5) max_off = 5;
        for (int bi = 0; bi < g_preview_nblobs; bi++) {
            blob_t *b = &g_preview_blobs[bi]; if (b->merged) continue;
            int ccx = (int)(mode == MODE_BODY ? b->body_cx : (double)b->cx);
            int ccy = (int)(mode == MODE_BODY ? b->body_cy : (double)b->cy);
            double f = b->grid_valid ? b->offset_total_px / max_off : 0;
            rgb_cross(g_preview_rgb, w, h, ccx, ccy, f, 5);
        }
    }

    /* Info string */
    int mg = 0; for (int i = 0; i < g_preview_nblobs; i++) if (g_preview_blobs[i].merged) mg++;
    char grid_info[128] = "";
    if (g_preview_gp.valid)
        snprintf(grid_info, sizeof(grid_info), "  |  grid: %.1fx%.1f px, %.2f\xC2\xB0",
            g_preview_gp.spacing_x, g_preview_gp.spacing_y,
            g_preview_gp.angle * 180.0 / PI);
    if (g_preview_missed_dots > 0)
        snprintf(g_preview_info, sizeof(g_preview_info),
            "thresh=%d  area>=%d  |  %d dots, %d merged, %d missed  |  smallest=%d px%s",
            thresh, min_area, g_preview_nblobs, mg, g_preview_missed_dots,
            g_preview_nblobs > 0 ? g_preview_min_area_detected : 0, grid_info);
    else
        snprintf(g_preview_info, sizeof(g_preview_info),
            "thresh=%d  area>=%d  |  %d dots, %d merged  |  smallest=%d px%s",
            thresh, min_area, g_preview_nblobs, mg,
            g_preview_nblobs > 0 ? g_preview_min_area_detected : 0, grid_info);
}

/* ================================================================
 *  SECTION 11 — PREVIEW NAVIGATION
 * ================================================================ */
static void update_imgnum_label(void) {
    if (g_preview_nfiles == 0) { strcpy(g_imgnum_label, "No images"); return; }
    const char *bn = strrchr(g_preview_files[g_preview_index], '\\');
    if (bn) bn++; else bn = g_preview_files[g_preview_index];
    snprintf(g_imgnum_label, sizeof(g_imgnum_label), "%d / %d : %s",
        g_preview_index + 1, g_preview_nfiles, bn);
}

static void reset_zoom(void) { g_zoom = 1.0; g_pan_x = g_pan_y = 0; }

static void load_preview_at_index(void) {
    g_preview_valid = 0; pgm_free(&g_preview_img);
    if (g_preview_rgb) { free(g_preview_rgb); g_preview_rgb = NULL; }
    reset_zoom();
    if (g_preview_nfiles == 0) return;
    if (g_preview_index < 0) g_preview_index = 0;
    if (g_preview_index >= g_preview_nfiles) g_preview_index = g_preview_nfiles - 1;
    if (!pgm_load(g_preview_files[g_preview_index], &g_preview_img)) return;
    g_preview_rgb = (uint8_t*)malloc(g_preview_img.width * g_preview_img.height * 3);
    if (!g_preview_rgb) { pgm_free(&g_preview_img); return; }
    g_preview_valid = 1;
    build_preview_rgb();
    update_imgnum_label();
}

static void scan_folder_for_preview(void) {
    g_preview_nfiles = find_pgm_files(g_folder_a, g_preview_files, MAX_FILES);
    g_preview_index = 0;
    load_preview_at_index();
}

/* ================================================================
 *  SECTION 12 — CONFIG SAVE/LOAD (file-based, no Win32 controls)
 * ================================================================ */
static void get_config_path(wchar_t *out, int mx) {
    GetModuleFileNameW(NULL, out, mx);
    wchar_t *s = wcsrchr(out, L'\\');
    if (s) wcscpy(s + 1, CONFIG_FILENAME); else wcscpy(out, CONFIG_FILENAME);
}

static void save_config(void) {
    wchar_t p[MAX_PATH]; get_config_path(p, MAX_PATH);
    FILE *f = _wfopen(p, L"w"); if (!f) return;
    fprintf(f, "px_per_mm=%s\n", g_pxmm_buf);
    fprintf(f, "threshold=%d\n", g_threshold);
    fprintf(f, "auto_threshold=%d\n", g_auto_thresh);
    fprintf(f, "min_area=%d\n", g_min_area);
    fprintf(f, "erosion=%d\n", g_erosion);
    fprintf(f, "mode=%d\n", g_mode);
    fprintf(f, "grid_pattern=%d\n", g_grid_pattern);
    fprintf(f, "crosshairs=%d\n", g_show_cross);
    fprintf(f, "grid_overlay=%d\n", g_show_grid);
    fprintf(f, "image_folder=%s\n", g_folder_a);
    fprintf(f, "output_folder=%s\n", g_outfolder_a);
    fclose(f);
}

/* Walk a path back to the nearest existing directory, or clear it */
static void resolve_path_fallback(char *path_a, wchar_t *path_w, int mx) {
    if (!strlen(path_a)) return;
    while (strlen(path_a) > 0) {
        DWORD attr = GetFileAttributesA(path_a);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
            break;
        /* Strip last component */
        char *sep = strrchr(path_a, '\\');
        if (!sep) sep = strrchr(path_a, '/');
        if (sep && sep != path_a) *sep = 0;
        else { path_a[0] = 0; break; }
    }
    if (strlen(path_a))
        MultiByteToWideChar(CP_ACP, 0, path_a, -1, path_w, mx);
    else
        path_w[0] = 0;
}

static void load_config(void) {
    wchar_t p[MAX_PATH]; get_config_path(p, MAX_PATH);
    FILE *f = _wfopen(p, L"r"); if (!f) return;
    char line[MAX_PATH_LEN + 64];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '='); if (!eq) continue;
        char *nl = strchr(eq + 1, '\n'); if (nl) *nl = 0;
        nl = strchr(eq + 1, '\r'); if (nl) *nl = 0;
        char *val = eq + 1;
        int kl = (int)(eq - line);
        if (kl == 9 && strncmp(line, "px_per_mm", 9) == 0) {
            strncpy(g_pxmm_buf, val, sizeof(g_pxmm_buf) - 1);
        } else if (kl == 9 && strncmp(line, "threshold", 9) == 0) {
            int v = atoi(val); if (v >= 1 && v <= 254) g_threshold = v;
        } else if (kl == 14 && strncmp(line, "auto_threshold", 14) == 0) {
            g_auto_thresh = atoi(val) ? 1 : 0;
        } else if (kl == 8 && strncmp(line, "min_area", 8) == 0) {
            int v = atoi(val); if (v >= 10 && v <= 2000) g_min_area = v;
        } else if (kl == 7 && strncmp(line, "erosion", 7) == 0) {
            int v = atoi(val); if (v >= 1 && v <= 15) g_erosion = v;
        } else if (kl == 4 && strncmp(line, "mode", 4) == 0) {
            int v = atoi(val); if (v >= 0 && v <= 1) g_mode = v;
        } else if (kl == 12 && strncmp(line, "grid_pattern", 12) == 0) {
            int v = atoi(val); if (v >= 0 && v <= 1) g_grid_pattern = v;
        } else if (kl == 10 && strncmp(line, "crosshairs", 10) == 0) {
            g_show_cross = atoi(val) ? 1 : 0;
        } else if (kl == 12 && strncmp(line, "grid_overlay", 12) == 0) {
            g_show_grid = atoi(val) ? 1 : 0;
        } else if (kl == 12 && strncmp(line, "image_folder", 12) == 0) {
            strncpy(g_folder_a, val, MAX_PATH_LEN - 1); g_folder_a[MAX_PATH_LEN - 1] = 0;
        } else if (kl == 13 && strncmp(line, "output_folder", 13) == 0) {
            strncpy(g_outfolder_a, val, MAX_PATH_LEN - 1); g_outfolder_a[MAX_PATH_LEN - 1] = 0;
        }
    }
    fclose(f);
    /* Validate saved paths — walk back if they no longer exist */
    resolve_path_fallback(g_folder_a, g_folder_w, MAX_PATH_LEN);
    resolve_path_fallback(g_outfolder_a, g_outfolder_w, MAX_PATH_LEN);
}

/* ================================================================
 *  SECTION 13 — RECORD MODE HELPERS
 * ================================================================ */
static void refresh_interfaces(void) {
    g_iface_count = 0;
    if (!load_npcap()) {
        strcpy(g_iface_descs[0], "Npcap not installed");
        g_iface_count = 1; g_iface_sel = 0; return;
    }
    char errbuf[PCAP_ERRBUF_SIZE]; pcap_if_t *alldevs;
    if (p_findalldevs(&alldevs, errbuf) == -1) return;
    pcap_if_t *d;
    for (d = alldevs; d && g_iface_count < MAX_IFACES; d = d->next) {
        strncpy(g_iface_names[g_iface_count], d->name, 511);
        char desc[256] = "";
        if (d->description) snprintf(desc, sizeof(desc), "%s", d->description);
        else snprintf(desc, sizeof(desc), "Interface %d", g_iface_count + 1);
        struct pcap_addr *a;
        for (a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                unsigned char *b = (unsigned char *)&sin->sin_addr;
                int len = (int)strlen(desc);
                snprintf(desc + len, sizeof(desc) - len, "  [%d.%d.%d.%d]", b[0], b[1], b[2], b[3]);
                break;
            }
        }
        strncpy(g_iface_descs[g_iface_count], desc, 255);
        g_iface_count++;
    }
    p_freealldevs(alldevs);
    if (g_iface_count > 0) g_iface_sel = 0;
}

static void start_recording(void) {
    if (g_rec_state != REC_IDLE) return;
    if (!load_npcap()) return;
    if (g_iface_sel < 0 || g_iface_sel >= g_iface_count) return;
    if (strlen(g_outfolder_a) == 0) return;
    CreateDirectoryA(g_outfolder_a, NULL);
    double sec = atof(g_stable_sec_buf);
    if (sec < 0.05) sec = 0.05; if (sec > 5.0) sec = 5.0;
    double mad_th = atof(g_mad_thresh_buf);
    if (mad_th < 1.0) mad_th = 1.0; if (mad_th > 100.0) mad_th = 100.0;
    strncpy(g_rec_iface, g_iface_names[g_iface_sel], sizeof(g_rec_iface) - 1);
    strncpy(g_rec_outdir, g_outfolder_a, sizeof(g_rec_outdir) - 1);
    g_rec_stable_sec = sec; g_rec_mad_thresh = mad_th;
    g_rec_stop = 0; g_rec_save_count = 0;
    EnterCriticalSection(&g_rec_cs);
    g_rec_state = REC_DISCOVERING;
    LeaveCriticalSection(&g_rec_cs);
    strcpy(g_rec_status, "Starting capture...");
    g_rec_thread = CreateThread(NULL, 0, recording_thread, NULL, 0, NULL);
    if (!g_rec_thread) {
        EnterCriticalSection(&g_rec_cs); g_rec_state = REC_IDLE; LeaveCriticalSection(&g_rec_cs);
    }
}

static void stop_recording(void) {
    if (g_rec_state == REC_IDLE) return;
    g_rec_stop = 1;
    strcpy(g_rec_status, "Stopping...");
    if (g_rec_thread) { WaitForSingleObject(g_rec_thread, 5000); CloseHandle(g_rec_thread); g_rec_thread = NULL; }
    EnterCriticalSection(&g_rec_cs); g_rec_state = REC_IDLE; LeaveCriticalSection(&g_rec_cs);
    if (g_rec_save_count > 0 && strcmp(g_outfolder_a, g_folder_a) == 0)
        scan_folder_for_preview();
}

/* ================================================================
 *  SECTION 14 — BATCH PROCESSING (preserved, adapted for no Win32 controls)
 * ================================================================ */
static void process_images(void) {
    if (!strlen(g_folder_a)) return;
    double px_mm = atof(g_pxmm_buf);
    if (px_mm <= 0) return;
    int auto_th = g_auto_thresh, manual_th = g_threshold;
    int min_area = g_min_area, erosion_r = g_erosion, mode = g_mode;
    int gridpat = g_grid_pattern;
    save_config();

    static char files[MAX_FILES][MAX_PATH_LEN];
    int nfiles = find_pgm_files(g_folder_a, files, MAX_FILES);
    if (!nfiles) { snprintf(g_status_text, sizeof(g_status_text), "No .pgm files found."); return; }
    snprintf(g_status_text, sizeof(g_status_text), "Found %d PGM files. Processing...", nfiles);
    g_progress_max = nfiles; g_progress_val = 0; g_processing = 1;

    char of[MAX_PATH_LEN]; snprintf(of, MAX_PATH_LEN, "%s\\annotated", g_folder_a);
    CreateDirectoryA(of, NULL);
    char cp[MAX_PATH_LEN]; snprintf(cp, MAX_PATH_LEN, "%s\\dot_measurements.csv", g_folder_a);
    FILE *csv = fopen(cp, "w");
    if (!csv) { g_processing = 0; return; }
    fprintf(csv, "File,Dot_Index,Centroid_X,Centroid_Y,"
        "BBox_W_px,BBox_H_px,BBox_Diam_px,BBox_Diam_mm,"
        "Body_Major_px,Body_Diam_mm,"
        "Area_px,Circularity_Raw,Circularity_Body,"
        "Grid_Row,Grid_Col,Offset_X_mm,Offset_Y_mm,Distance_Error_mm,Merged_Flag\n");

    int total_missed = 0;
    stats_t gs_d, gs_cr, gs_cb, gs_ox, gs_oy, gs_dist;
    si(&gs_d, 50000); si(&gs_cr, 50000); si(&gs_cb, 50000);
    si(&gs_ox, 50000); si(&gs_oy, 50000); si(&gs_dist, 50000);
    int td = 0, tm = 0;

    grid_params_t gp = {0};
    { int bfi = 0, bc = 0;
      for (int fi = 0; fi < nfiles && fi < 10; fi++) {
          pgm_image_t img;
          if (!pgm_load(files[fi], &img)) continue;
          int th = auto_th ? compute_otsu(img.pixels, img.width * img.height) : manual_th;
          static blob_t tb[MAX_BLOBS];
          int nb = process_image_light(&img, th, min_area, tb, MAX_BLOBS);
          int gd = 0; for (int i = 0; i < nb; i++) if (!tb[i].merged) gd++;
          if (gd > bc) { bc = gd; bfi = fi; } pgm_free(&img); }
      pgm_image_t img;
      if (pgm_load(files[bfi], &img)) {
          int th = auto_th ? compute_otsu(img.pixels, img.width * img.height) : manual_th;
          static blob_t tb[MAX_BLOBS];
          int nb = process_image_full(&img, th, min_area, erosion_r, tb, MAX_BLOBS);
          int iw = img.width, ih = img.height;
          if (gridpat == GRIDPAT_STAGGERED) infer_grid_params_checker(tb, nb, &gp, mode == MODE_BODY, iw, ih);
          else infer_grid_params(tb, nb, &gp, gridpat, mode == MODE_BODY, iw, ih);
          pgm_free(&img); }
    }

    for (int fi = 0; fi < nfiles; fi++) {
        pgm_image_t img;
        if (!pgm_load(files[fi], &img)) { g_progress_val = fi + 1; continue; }
        int thresh = auto_th ? compute_otsu(img.pixels, img.width * img.height) : manual_th;
        static blob_t blobs[MAX_BLOBS];
        int nb = process_image_full(&img, thresh, min_area, erosion_r, blobs, MAX_BLOBS);
        for (int i = 0; i < nb; i++) {
            blobs[i].diameter_mm = (double)blobs[i].diameter_px / px_mm;
            blobs[i].body_diameter_mm = blobs[i].body_major_px / px_mm;
        }
        compute_grid_offsets(blobs, nb, &gp, px_mm, mode == MODE_BODY);
        int file_missed = 0;
        if (gp.valid) file_missed = count_missed_dots(blobs, nb, &gp, img.width, img.height);
        total_missed += file_missed;
        const char *bn = strrchr(files[fi], '\\'); if (bn) bn++; else bn = files[fi];
        stats_t fs; si(&fs, nb + 1);
        for (int i = 0; i < nb; i++) {
            blob_t *b = &blobs[i];
            double pd = (mode == MODE_BODY) ? b->body_diameter_mm : b->diameter_mm;
            double dist_err = b->grid_valid ? sqrt(b->offset_x_mm * b->offset_x_mm + b->offset_y_mm * b->offset_y_mm) : 0.0;
            fprintf(csv, "%s,%d,%d,%d,%d,%d,%d,%.4f,%.1f,%.4f,%d,%.3f,%.3f,%d,%d,%.4f,%.4f,%.4f,%s\n",
                bn, i + 1, b->cx, b->cy, b->bb_w, b->bb_h, b->diameter_px, b->diameter_mm,
                b->body_major_px, b->body_diameter_mm, b->area, b->circularity_raw, b->circularity_body,
                b->grid_valid ? b->grid_row : -1, b->grid_valid ? b->grid_col : -1,
                b->grid_valid ? b->offset_x_mm : 0.0, b->grid_valid ? b->offset_y_mm : 0.0,
                b->grid_valid ? dist_err : 0.0, b->merged ? "YES" : "NO");
            if (!b->merged) {
                sa(&gs_d, pd); sa(&fs, pd);
                sa(&gs_cr, b->circularity_raw); sa(&gs_cb, b->circularity_body);
                if (b->grid_valid) { sa(&gs_ox, fabs(b->offset_x_mm)); sa(&gs_oy, fabs(b->offset_y_mm)); sa(&gs_dist, dist_err); }
            }
            td++; if (b->merged) tm++;
        }
        if (fs.count > 0) {
            fprintf(csv, "%s,SUMMARY,,,,,,,,,,,,,,,,,\n", bn);
            fprintf(csv, "%s,Count,%d,,,,,,,,,,,,,,,\n", bn, fs.count);
            fprintf(csv, "%s,Missed,%d,,,,,,,,,,,,,,,\n", bn, file_missed);
            fprintf(csv, "%s,Mean,,,,,,,,%.4f,,,,,,,,\n", bn, smean(&fs));
            fprintf(csv, "%s,Median,,,,,,,,%.4f,,,,,,,,\n", bn, smed(&fs));
            fprintf(csv, "%s,StdDev,,,,,,,,%.4f,,,,,,,,\n", bn, sstd(&fs));
            fprintf(csv, "%s,Min,,,,,,,,%.4f,,,,,,,,\n", bn, fs.min_val);
            fprintf(csv, "%s,Max,,,,,,,,%.4f,,,,,,,,\n", bn, fs.max_val);
        }
        sfree(&fs);
        /* Annotate */
        for (int i = 0; i < nb; i++) {
            blob_t *b = &blobs[i];
            int bx0, by0, bx1, by1;
            if (mode == MODE_BODY) {
                bx0 = b->body_min_x - BORDER_PAD; by0 = b->body_min_y - BORDER_PAD;
                bx1 = b->body_max_x + BORDER_PAD; by1 = b->body_max_y + BORDER_PAD;
            } else {
                bx0 = b->min_x - BORDER_PAD; by0 = b->min_y - BORDER_PAD;
                bx1 = b->max_x + BORDER_PAD; by1 = b->max_y + BORDER_PAD;
            }
            if (bx0 < 0) bx0 = 0; if (by0 < 0) by0 = 0;
            if (bx1 >= img.width) bx1 = img.width - 1; if (by1 >= img.height) by1 = img.height - 1;
            drect(&img, bx0, by0, bx1, by1, 255);
            if (b->merged) drect(&img, bx0 + 1, by0 + 1, bx1 - 1, by1 - 1, 255);
            char label[32]; double dd = (mode == MODE_BODY) ? b->body_diameter_mm : b->diameter_mm;
            if (b->merged) snprintf(label, 32, "MRGD"); else snprintf(label, 32, "%.2f", dd);
            int tw = (int)strlen(label) * (FONT_W + 1);
            int tx = b->cx - tw / 2, ty = by1 - FONT_H - 2;
            if (tx < bx0 + 2) tx = bx0 + 2; if (tx + tw > bx1 - 2) tx = bx1 - tw - 2; if (ty < by0 + 2) ty = by0 + 2;
            uint8_t tc2 = tcol(&img, tx, ty, tx + tw, ty + FONT_H);
            for (int py = ty - 1; py <= ty + FONT_H; py++) for (int px = tx - 1; px <= tx + tw; px++)
                dpx(&img, px, py, (tc2 == 255) ? 0 : 200);
            dstr(&img, tx, ty, label, tc2);
        }
        char op[MAX_PATH_LEN]; snprintf(op, MAX_PATH_LEN, "%s\\%s", of, bn);
        pgm_save(op, &img); pgm_free(&img);
        g_progress_val = fi + 1;
        snprintf(g_status_text, sizeof(g_status_text), "Processed %d/%d: %s (%d dots)", fi + 1, nfiles, bn, nb);
        /* Pump messages to keep UI responsive */
        MSG msg; while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    }

    fprintf(csv, "\n\nGLOBAL SUMMARY\n");
    fprintf(csv, "Total Files,%d\n", nfiles);
    fprintf(csv, "Total Dots (non-merged),%d\n", gs_d.count);
    fprintf(csv, "Total Merged,%d\n", tm);
    fprintf(csv, "Total Missed,%d\n", total_missed);
    fprintf(csv, "Mode,%s\n", mode == MODE_BODY ? "Body Detection" : "Bounding Box");
    fprintf(csv, "Grid Pattern,%s\n", gridpat == GRIDPAT_STAGGERED ? "Checker / Staggered" : "Rectangular");
    fprintf(csv, "Pixels/mm,%.4f\n", px_mm);
    if (gp.valid) {
        fprintf(csv, "Grid Spacing X (px),%.2f\n", gp.spacing_x);
        fprintf(csv, "Grid Spacing Y (px),%.2f\n", gp.spacing_y);
        fprintf(csv, "Grid Angle (deg),%.3f\n", gp.angle * 180.0 / PI);
        if (gp.staggered && fabs(gp.stagger_y) > 0.01)
            fprintf(csv, "Stagger Y (px),%.2f\n", gp.stagger_y);
    }
    if (gs_d.count > 0) { fprintf(csv, "\nDiameter (mm)\n");
        fprintf(csv, "Mean,%.4f\nMedian,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_d), smed(&gs_d), sstd(&gs_d), gs_d.min_val, gs_d.max_val); }
    if (gs_cr.count > 0) { fprintf(csv, "\nCircularity Raw\n");
        fprintf(csv, "Mean,%.4f\nMedian,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_cr), smed(&gs_cr), sstd(&gs_cr), gs_cr.min_val, gs_cr.max_val); }
    if (gs_cb.count > 0) { fprintf(csv, "\nCircularity Body\n");
        fprintf(csv, "Mean,%.4f\nMedian,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_cb), smed(&gs_cb), sstd(&gs_cb), gs_cb.min_val, gs_cb.max_val); }
    if (gs_ox.count > 0) {
        fprintf(csv, "\nGrid Offset X Abs (mm)\nMean,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_ox), sstd(&gs_ox), gs_ox.min_val, gs_ox.max_val);
        fprintf(csv, "\nGrid Offset Y Abs (mm)\nMean,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_oy), sstd(&gs_oy), gs_oy.min_val, gs_oy.max_val);
    }
    if (gs_dist.count > 0) {
        fprintf(csv, "\nDistance Error (mm)\nMean,%.4f\nMedian,%.4f\nStdDev,%.4f\nMin,%.4f\nMax,%.4f\n",
            smean(&gs_dist), smed(&gs_dist), sstd(&gs_dist), gs_dist.min_val, gs_dist.max_val);
    }
    fclose(csv);

    snprintf(g_status_text, sizeof(g_status_text),
        "Done! %d files, %d dots (%d merged, %d missed). CSV: %s",
        nfiles, td, tm, total_missed, cp);
    g_processing = 0;
    sfree(&gs_d); sfree(&gs_cr); sfree(&gs_cb); sfree(&gs_ox); sfree(&gs_oy); sfree(&gs_dist);
}

/* ================================================================
 *  SECTION 15 — FOLDER BROWSE DIALOGS
 * ================================================================ */
static int CALLBACK browse_callback(HWND hwnd, UINT msg, LPARAM, LPARAM data) {
    if (msg == BFFM_INITIALIZED && data)
        SendMessageW(hwnd, BFFM_SETSELECTIONW, TRUE, data);
    return 0;
}

static void browse_folder_dialog(char *out_a, wchar_t *out_w, int mx, const wchar_t *title) {
    /* Resolve starting path: use current value, walk back if it doesn't exist */
    wchar_t start[MAX_PATH] = L"";
    if (wcslen(out_w) > 0) {
        wcsncpy(start, out_w, MAX_PATH - 1);
        while (wcslen(start) > 0) {
            DWORD attr = GetFileAttributesW(start);
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
                break;
            wchar_t *sep = wcsrchr(start, L'\\');
            if (sep && sep != start) *sep = 0;
            else { start[0] = 0; break; }
        }
    }

    BROWSEINFOW bi = {0}; bi.hwndOwner = g_hwnd;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    bi.lpfn = browse_callback;
    bi.lParam = (LPARAM)(wcslen(start) > 0 ? start : NULL);
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        wchar_t p[MAX_PATH];
        if (SHGetPathFromIDListW(pidl, p)) {
            wcsncpy(out_w, p, mx);
            WideCharToMultiByte(CP_ACP, 0, p, -1, out_a, mx, NULL, NULL);
        }
        CoTaskMemFree(pidl);
    }
}
/* ================================================================
 *  SECTION 16 — OpenGL PREVIEW TEXTURE
 * ================================================================ */
#ifndef GL_BGR_EXT
#define GL_BGR_EXT 0x80E0
#endif

static GLuint g_preview_tex = 0;
static int    g_tex_w = 0, g_tex_h = 0;
static float  g_dpi_scale = 1.0f;
static float  g_left_panel_w = 420.0f;

static void upload_preview_texture(void) {
    if (!g_preview_valid || !g_preview_rgb) return;
    int w = g_preview_img.width, h = g_preview_img.height;
    if (!g_preview_tex) {
        glGenTextures(1, &g_preview_tex);
    }
    glBindTexture(GL_TEXTURE_2D, g_preview_tex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    /* g_preview_rgb is in BGR order (from rgb_px), upload with GL_BGR_EXT */
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, w, h, 0, GL_BGR_EXT, GL_UNSIGNED_BYTE, g_preview_rgb);
    g_tex_w = w; g_tex_h = h;
}

/* ================================================================
 *  SECTION 17 — ImGui DARK THEME
 * ================================================================ */
static void setup_theme() {
    ImGuiStyle &s = ImGui::GetStyle();
    ImVec4 *c = s.Colors;

    ImVec4 bg      = ImVec4(0.11f, 0.11f, 0.13f, 1.0f);
    ImVec4 panel   = ImVec4(0.14f, 0.14f, 0.16f, 1.0f);
    ImVec4 widget  = ImVec4(0.20f, 0.20f, 0.23f, 1.0f);
    ImVec4 hover   = ImVec4(0.25f, 0.25f, 0.30f, 1.0f);
    ImVec4 active  = ImVec4(0.18f, 0.18f, 0.22f, 1.0f);
    ImVec4 accent  = ImVec4(0.16f, 0.50f, 0.86f, 1.0f);
    ImVec4 accentH = ImVec4(0.20f, 0.58f, 0.94f, 1.0f);
    ImVec4 text    = ImVec4(0.86f, 0.87f, 0.90f, 1.0f);
    ImVec4 textDim = ImVec4(0.50f, 0.52f, 0.56f, 1.0f);

    c[ImGuiCol_WindowBg]        = bg;
    c[ImGuiCol_ChildBg]         = panel;
    c[ImGuiCol_PopupBg]         = ImVec4(0.12f, 0.12f, 0.15f, 0.96f);
    c[ImGuiCol_Border]          = ImVec4(0.22f, 0.22f, 0.26f, 0.6f);
    c[ImGuiCol_FrameBg]         = widget;
    c[ImGuiCol_FrameBgHovered]  = hover;
    c[ImGuiCol_FrameBgActive]   = active;
    c[ImGuiCol_TitleBg]         = panel;
    c[ImGuiCol_TitleBgActive]   = ImVec4(0.16f, 0.16f, 0.19f, 1.0f);
    c[ImGuiCol_MenuBarBg]       = panel;
    c[ImGuiCol_ScrollbarBg]     = bg;
    c[ImGuiCol_ScrollbarGrab]       = widget;
    c[ImGuiCol_ScrollbarGrabHovered]= hover;
    c[ImGuiCol_ScrollbarGrabActive] = active;
    c[ImGuiCol_CheckMark]       = accent;
    c[ImGuiCol_SliderGrab]      = accent;
    c[ImGuiCol_SliderGrabActive]= accentH;
    c[ImGuiCol_Button]          = widget;
    c[ImGuiCol_ButtonHovered]   = hover;
    c[ImGuiCol_ButtonActive]    = active;
    c[ImGuiCol_Header]          = widget;
    c[ImGuiCol_HeaderHovered]   = hover;
    c[ImGuiCol_HeaderActive]    = active;
    c[ImGuiCol_Separator]       = ImVec4(0.22f, 0.22f, 0.26f, 0.6f);
    c[ImGuiCol_Tab]             = widget;
    c[ImGuiCol_TabHovered]      = hover;
    c[ImGuiCol_Text]            = text;
    c[ImGuiCol_TextDisabled]    = textDim;

    s.WindowRounding    = 0.0f;
    s.ChildRounding     = 4.0f;
    s.FrameRounding     = 4.0f;
    s.GrabRounding      = 3.0f;
    s.PopupRounding     = 4.0f;
    s.ScrollbarRounding = 4.0f;
    s.TabRounding       = 4.0f;
    s.WindowPadding     = ImVec2(12, 12);
    s.FramePadding      = ImVec2(8, 4);
    s.ItemSpacing       = ImVec2(8, 6);
    s.ItemInnerSpacing  = ImVec2(6, 4);
    s.ScrollbarSize     = 12.0f;
    s.GrabMinSize       = 10.0f;
}

static void section_header(const char *label) {
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.47f, 0.67f, 0.90f, 1.0f));
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::Spacing();
}

/* ================================================================
 *  SECTION 18 — ImGui UI DRAWING
 * ================================================================ */
static void draw_ui(void) {
    int prev_dirty = 0;

    ImGuiViewport *vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->Pos);
    ImGui::SetNextWindowSize(vp->Size);
    ImGui::Begin("##Main", NULL,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollbar);

    float total_w = ImGui::GetContentRegionAvail().x;
    float total_h = ImGui::GetContentRegionAvail().y;

    /* ---- LEFT PANEL ---- */
    ImGui::BeginChild("##LeftPanel", ImVec2(g_left_panel_w, total_h), true);
    {
        /* -- Image Folder -- */
        section_header("IMAGE FOLDER");
        ImGui::Text("Path: %s", strlen(g_folder_a) ? g_folder_a : "(none)");
        if (ImGui::Button("Browse...", ImVec2(-1, 0))) {
            browse_folder_dialog(g_folder_a, g_folder_w, MAX_PATH_LEN,
                L"Select folder containing PGM images");
            scan_folder_for_preview();
            prev_dirty = 1;
        }

        /* -- Calibration -- */
        section_header("CALIBRATION");
        ImGui::SetNextItemWidth(120 * g_dpi_scale);
        ImGui::InputText("Pixels/mm", g_pxmm_buf, sizeof(g_pxmm_buf));

        const char *modes[] = { "Bounding Box", "Body Detection" };
        ImGui::SetNextItemWidth(180 * g_dpi_scale);
        int new_mode = g_mode;
        ImGui::Combo("Measurement", &new_mode, modes, 2);
        if (new_mode != g_mode) { g_mode = new_mode; prev_dirty = 1; }

        /* -- Threshold -- */
        section_header("THRESHOLD");
        bool auto_th = (g_auto_thresh != 0);
        if (ImGui::Checkbox("Auto threshold (Otsu)", &auto_th)) {
            g_auto_thresh = auto_th ? 1 : 0; prev_dirty = 1;
        }
        if (!g_auto_thresh) {
            ImGui::Text("Threshold:");
            ImGui::SetNextItemWidth(-(80 * g_dpi_scale));
            int new_th = g_threshold;
            ImGui::SliderInt("##thresh", &new_th, 1, 254);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(-1);
            ImGui::InputInt("##thresh_in", &new_th, 0, 0);
            if (new_th < 1) new_th = 1; if (new_th > 254) new_th = 254;
            if (new_th != g_threshold) { g_threshold = new_th; prev_dirty = 1; }
        } else {
            ImGui::TextDisabled("  Auto value: %d", g_threshold);
        }

        /* -- Min Area -- */
        ImGui::Text("Min area (px):");
        ImGui::SetNextItemWidth(-(80 * g_dpi_scale));
        int new_ma = g_min_area;
        ImGui::SliderInt("##minarea", &new_ma, 10, 2000);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-1);
        ImGui::InputInt("##minarea_in", &new_ma, 0, 0);
        if (new_ma < 10) new_ma = 10; if (new_ma > 2000) new_ma = 2000;
        if (new_ma != g_min_area) { g_min_area = new_ma; prev_dirty = 1; }

        /* -- Erosion (body mode only) -- */
        if (g_mode == MODE_BODY) {
            ImGui::Text("Erosion (px):");
            ImGui::SetNextItemWidth(-(80 * g_dpi_scale));
            int new_er = g_erosion;
            ImGui::SliderInt("##erosion", &new_er, 1, 15);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(-1);
            ImGui::InputInt("##erosion_in", &new_er, 0, 0);
            if (new_er < 1) new_er = 1; if (new_er > 15) new_er = 15;
            if (new_er != g_erosion) { g_erosion = new_er; prev_dirty = 1; }
        }

        /* -- Overlays -- */
        section_header("OVERLAYS");
        bool sc = (g_show_cross != 0), sg = (g_show_grid != 0);
        if (ImGui::Checkbox("Crosshairs", &sc)) { g_show_cross = sc ? 1 : 0; prev_dirty = 1; }
        ImGui::SameLine(200 * g_dpi_scale);
        if (ImGui::Checkbox("Grid lines", &sg)) { g_show_grid = sg ? 1 : 0; prev_dirty = 1; }

        const char *pats[] = { "Rectangular", "Checker / Staggered" };
        ImGui::SetNextItemWidth(200 * g_dpi_scale);
        int new_gp = g_grid_pattern;
        ImGui::Combo("Grid pattern", &new_gp, pats, 2);
        if (new_gp != g_grid_pattern) { g_grid_pattern = new_gp; prev_dirty = 1; }

        /* -- Process Button -- */
        ImGui::Spacing(); ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.12f, 0.43f, 0.75f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,  ImVec4(0.16f, 0.51f, 0.86f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,   ImVec4(0.10f, 0.35f, 0.63f, 1.0f));
        if (ImGui::Button("Process All Images", ImVec2(-1, 36 * g_dpi_scale)) && !g_processing) {
            process_images();
        }
        ImGui::PopStyleColor(3);

        /* -- Progress -- */
        if (g_progress_max > 0) {
            float prog = (float)g_progress_val / (float)g_progress_max;
            char overlay[64];
            snprintf(overlay, sizeof(overlay), "%d / %d", g_progress_val, g_progress_max);
            ImGui::ProgressBar(prog, ImVec2(-1, 0), overlay);
        }
        ImGui::TextWrapped("%s", g_status_text);

        /* ---- RECORD MODE ---- */
        section_header("RECORD MODE");

        /* Interface selector */
        ImGui::SetNextItemWidth(-(60 * g_dpi_scale));
        if (g_iface_count > 0) {
            if (ImGui::BeginCombo("##iface", g_iface_descs[g_iface_sel])) {
                for (int i = 0; i < g_iface_count; i++) {
                    bool selected = (i == g_iface_sel);
                    if (ImGui::Selectable(g_iface_descs[i], selected))
                        g_iface_sel = i;
                    if (selected) ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
            }
        } else {
            ImGui::TextDisabled("(no interfaces)");
        }
        ImGui::SameLine();
        if (ImGui::Button("Scan")) {
            refresh_interfaces();
        }

        /* Output folder */
        ImGui::Text("Output: %s", strlen(g_outfolder_a) ? g_outfolder_a : "(none)");
        ImGui::SameLine();
        if (ImGui::Button("Browse##out")) {
            browse_folder_dialog(g_outfolder_a, g_outfolder_w, MAX_PATH_LEN,
                L"Select output folder for recorded frames");
        }

        /* Stability / MAD */
        ImGui::SetNextItemWidth(80 * g_dpi_scale);
        ImGui::InputText("Stable (s)", g_stable_sec_buf, sizeof(g_stable_sec_buf));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80 * g_dpi_scale);
        ImGui::InputText("MAD", g_mad_thresh_buf, sizeof(g_mad_thresh_buf));

        /* Record button */
        ImGui::Spacing();
        if (g_rec_state == REC_IDLE) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.63f, 0.16f, 0.16f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,  ImVec4(0.78f, 0.20f, 0.20f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,   ImVec4(0.51f, 0.12f, 0.12f, 1.0f));
            if (ImGui::Button("Start Recording", ImVec2(-1, 32 * g_dpi_scale)))
                start_recording();
            ImGui::PopStyleColor(3);
        } else {
            if (ImGui::Button("Stop Recording", ImVec2(-1, 32 * g_dpi_scale)))
                stop_recording();
        }
        ImGui::TextWrapped("%s", g_rec_status);
    }
    ImGui::EndChild();

    ImGui::SameLine();

    /* ---- RIGHT PANEL (Preview) ---- */
    ImGui::BeginChild("##RightPanel", ImVec2(0, total_h), true);
    {
        /* Nav bar */
        if (ImGui::ArrowButton("##prev", ImGuiDir_Left)) {
            if (g_preview_index > 0) { g_preview_index--; load_preview_at_index(); prev_dirty = 1; }
        }
        ImGui::SameLine();
        if (ImGui::ArrowButton("##next", ImGuiDir_Right)) {
            if (g_preview_index < g_preview_nfiles - 1) { g_preview_index++; load_preview_at_index(); prev_dirty = 1; }
        }
        ImGui::SameLine();
        {
            bool za = (g_zoom_active != 0);
            if (za) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f, 0.50f, 0.86f, 1.0f));
                if (ImGui::Button("Zoom")) { g_zoom_active = 0; }
                ImGui::PopStyleColor();
            } else {
                if (ImGui::Button("Zoom")) { g_zoom_active = 1; }
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Reset")) { reset_zoom(); }
        ImGui::SameLine();
        ImGui::Text("%s", g_imgnum_label);

        /* Info line */
        ImGui::TextDisabled("%s", g_preview_info);

        ImGui::Separator();

        /* Preview image */
        if (g_preview_valid && g_preview_tex && g_tex_w > 0) {
            ImVec2 avail = ImGui::GetContentRegionAvail();
            int iw = g_tex_w, ih = g_tex_h;

            /* Base scale: fit to panel, cap at 1:1 */
            float bs = 1.0f;
            { float fx = avail.x / (float)iw, fy = avail.y / (float)ih;
              bs = (fx < fy) ? fx : fy; if (bs > 1.0f) bs = 1.0f; }
            float es = bs * (float)g_zoom;

            float vis_w = avail.x / es, vis_h = avail.y / es;
            float cx = iw / 2.0f + (float)g_pan_x, cy = ih / 2.0f + (float)g_pan_y;
            if (cx < vis_w / 2) cx = vis_w / 2; if (cx > iw - vis_w / 2) cx = iw - vis_w / 2;
            if (cy < vis_h / 2) cy = vis_h / 2; if (cy > ih - vis_h / 2) cy = ih - vis_h / 2;
            g_pan_x = cx - iw / 2.0; g_pan_y = cy - ih / 2.0;

            float src_x = cx - vis_w / 2, src_y = cy - vis_h / 2;
            if (src_x < 0) src_x = 0; if (src_y < 0) src_y = 0;
            float src_w = vis_w, src_h = vis_h;
            if (src_x + src_w > iw) { src_w = iw - src_x; }
            if (src_y + src_h > ih) { src_h = ih - src_y; }

            /* UV coordinates for the visible region */
            ImVec2 uv0(src_x / iw, src_y / ih);
            ImVec2 uv1((src_x + src_w) / iw, (src_y + src_h) / ih);

            /* Display size: maintain aspect ratio of visible region */
            float disp_w, disp_h;
            { float fx = avail.x / src_w, fy = avail.y / src_h;
              float fit = (fx < fy) ? fx : fy;
              disp_w = src_w * fit; disp_h = src_h * fit; }

            /* Center in available area */
            float off_x = (avail.x - disp_w) * 0.5f;
            float off_y = (avail.y - disp_h) * 0.5f;
            if (off_x > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + off_x);
            if (off_y > 0) ImGui::SetCursorPosY(ImGui::GetCursorPosY() + off_y);

            /* Store preview rect for zoom/pan input detection */
            ImVec2 cpos = ImGui::GetCursorScreenPos();
            g_preview_rect.x = cpos.x; g_preview_rect.y = cpos.y;
            g_preview_rect.w = disp_w;  g_preview_rect.h = disp_h;

            /* Draw image via draw list, then overlay an InvisibleButton for interaction */
            ImVec2 p0 = cpos;
            ImVec2 p1 = ImVec2(cpos.x + disp_w, cpos.y + disp_h);
            ImGui::GetWindowDrawList()->AddImage(
                (ImTextureID)(intptr_t)g_preview_tex, p0, p1, uv0, uv1);
            ImGui::InvisibleButton("##preview_interact", ImVec2(disp_w, disp_h));

            /* Handle zoom via mouse wheel over preview */
            if (g_zoom_active && ImGui::IsItemHovered()) {
                float wheel = ImGui::GetIO().MouseWheel;
                if (wheel != 0) {
                    if (wheel > 0) { g_zoom *= 1.25; if (g_zoom > 16.0) g_zoom = 16.0; }
                    else { g_zoom /= 1.25; if (g_zoom < 1.0) g_zoom = 1.0; }
                    if (g_zoom <= 1.01) { g_pan_x = g_pan_y = 0; }
                }
            }

            /* Handle pan via drag */
            if (g_zoom_active && g_zoom > 1.01 && ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
                ImVec2 delta = ImGui::GetIO().MouseDelta;
                g_pan_x -= delta.x / es;
                g_pan_y -= delta.y / es;
            }
        } else {
            ImVec2 avail = ImGui::GetContentRegionAvail();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + avail.y * 0.45f);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + avail.x * 0.15f);
            ImGui::TextDisabled("No preview. Select a folder with PGM files.");
        }
    }
    ImGui::EndChild();

    ImGui::End();

    /* Rebuild preview if params changed */
    if (prev_dirty && g_preview_valid) {
        build_preview_rgb();
        upload_preview_texture();
    }
}

/* ================================================================
 *  SECTION 19 — OpenGL CONTEXT & WINDOW PROCEDURE
 * ================================================================ */
static HGLRC g_hrc = NULL;
static HDC   g_hdc = NULL;
static int   g_wnd_w = 1060, g_wnd_h = 720;

static bool create_gl_context(HWND hwnd) {
    g_hdc = GetDC(hwnd);
    PIXELFORMATDESCRIPTOR pfd = {};
    pfd.nSize = sizeof(pfd);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    pfd.cDepthBits = 24;
    pfd.cStencilBits = 8;
    int pf = ChoosePixelFormat(g_hdc, &pfd);
    if (!pf) return false;
    SetPixelFormat(g_hdc, pf, &pfd);
    g_hrc = wglCreateContext(g_hdc);
    if (!g_hrc) return false;
    wglMakeCurrent(g_hdc, g_hrc);
    return true;
}

static void destroy_gl_context() {
    if (g_hrc) { wglMakeCurrent(NULL, NULL); wglDeleteContext(g_hrc); g_hrc = NULL; }
    if (g_hdc) { ReleaseDC(g_hwnd, g_hdc); g_hdc = NULL; }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam))
        return 1;

    switch (msg) {
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) {
            g_wnd_w = LOWORD(lParam);
            g_wnd_h = HIWORD(lParam);
            glViewport(0, 0, g_wnd_w, g_wnd_h);
        }
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mm = (MINMAXINFO*)lParam;
        mm->ptMinTrackSize.x = MIN_WIN_W;
        mm->ptMinTrackSize.y = MIN_WIN_H;
        return 0;
    }
    /* Keyboard: left/right arrows for image navigation */
    case WM_KEYDOWN:
        if (wParam == VK_LEFT && g_preview_index > 0) {
            g_preview_index--; load_preview_at_index();
            upload_preview_texture(); return 0;
        }
        if (wParam == VK_RIGHT && g_preview_index < g_preview_nfiles - 1) {
            g_preview_index++; load_preview_at_index();
            upload_preview_texture(); return 0;
        }
        break;
    case WM_DESTROY:
        if (g_rec_state != REC_IDLE) stop_recording();
        save_config();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* ================================================================
 *  SECTION 20 — ENTRY POINT
 * ================================================================ */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nShow) {
    g_hinst = hInst;

    /* DPI awareness */
    {
        typedef BOOL (WINAPI *PFN_SetDpiCtx)(DPI_AWARENESS_CONTEXT);
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        PFN_SetDpiCtx pfn = (PFN_SetDpiCtx)GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        if (pfn) pfn(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        else SetProcessDPIAware();
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_BAR_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    InitializeCriticalSection(&g_rec_cs);

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Register window class */
    WNDCLASSW wc = {};
    wc.style = CS_OWNDC | CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = L"DotAnalyzerImGui";
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1));
    RegisterClassW(&wc);

    g_hwnd = CreateWindowW(L"DotAnalyzerImGui", L"Dot Analyzer  v8.0",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        MIN_WIN_W, MIN_WIN_H, NULL, NULL, hInst, NULL);

    if (!create_gl_context(g_hwnd)) {
        MessageBoxW(NULL, L"Failed to create OpenGL context", L"Error", MB_OK);
        return 1;
    }

    ShowWindow(g_hwnd, nShow);
    UpdateWindow(g_hwnd);

    /* Setup ImGui */
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    /* Keyboard nav disabled — arrow keys reserved for image navigation */
    io.IniFilename = NULL;

    setup_theme();

    /* Compute DPI scale */
    {
        typedef UINT (WINAPI *PFN_GetDpiForWindow)(HWND);
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        PFN_GetDpiForWindow pfn = (PFN_GetDpiForWindow)GetProcAddress(user32, "GetDpiForWindow");
        if (pfn) g_dpi_scale = (float)pfn(g_hwnd) / 96.0f;
        else {
            HDC screen = GetDC(NULL);
            g_dpi_scale = (float)GetDeviceCaps(screen, LOGPIXELSX) / 96.0f;
            ReleaseDC(NULL, screen);
        }
        if (g_dpi_scale < 1.0f) g_dpi_scale = 1.0f;
    }

    ImGui::GetStyle().ScaleAllSizes(g_dpi_scale);
    g_left_panel_w = 420.0f * g_dpi_scale;

    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", floorf(15.0f * g_dpi_scale));
    io.FontGlobalScale = 1.0f;

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplOpenGL3_Init("#version 130");

    /* Enable VSync to cap frame rate to monitor refresh */
    {
        typedef BOOL (WINAPI *PFN_wglSwapIntervalEXT)(int);
        PFN_wglSwapIntervalEXT wglSwapInterval =
            (PFN_wglSwapIntervalEXT)wglGetProcAddress("wglSwapIntervalEXT");
        if (wglSwapInterval) wglSwapInterval(1);
    }

    /* Load config, populate interfaces, load first preview */
    load_config();
    refresh_interfaces();
    if (strlen(g_folder_a)) {
        scan_folder_for_preview();
        if (g_preview_valid) upload_preview_texture();
    }

    /* Main loop */
    bool running = true;
    while (running) {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { running = false; break; }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (!running) break;

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        draw_ui();

        ImGui::Render();
        glViewport(0, 0, g_wnd_w, g_wnd_h);
        glClearColor(0.11f, 0.11f, 0.13f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SwapBuffers(g_hdc);

        /* If VSync isn't working, fall back to ~60fps cap */
        Sleep(1);
    }

    /* Cleanup */
    if (g_preview_tex) glDeleteTextures(1, &g_preview_tex);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    destroy_gl_context();

    pgm_free(&g_preview_img);
    if (g_preview_rgb) free(g_preview_rgb);
    DeleteCriticalSection(&g_rec_cs);
    if (g_wpcap_dll) FreeLibrary(g_wpcap_dll);
    WSACleanup();
    CoUninitialize();

    return 0;
}
