# Dot Analyzer v8.2.1 — ImGui + OpenGL3 Edition

Analyzes PGM images of dispensed fluid dots on a substrate. Measures diameter, circularity, XY grid offset, and flags missed/merged dots across batches of images. Includes live GVSP packet capture from Basler cameras via Npcap.

## Quick Start

1. Download ImGui from https://github.com/ocornut/imgui
2. Place `imgui/` folder next to `dot_analyzer_v8.2.1.cpp`
3. Run `build.bat`

## Dependencies

- **Dear ImGui** — core + Win32/OpenGL3 backends
- **MinGW-w64** — g++ compiler
- **Npcap** (optional) — for Record Mode camera capture

## Build

```bat
g++ dot_analyzer_v8.2.1.cpp imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp imgui/backends/imgui_impl_win32.cpp imgui/backends/imgui_impl_opengl3.cpp -o "Dot Analyzer.exe" -I./imgui -I./imgui/backends -lgdi32 -lopengl32 -ldwmapi -lcomdlg32 -lcomctl32 -lole32 -lshell32 -lshlwapi -lws2_32 -mwindows -O2 -DUNICODE -D_UNICODE
```

## Languages

The UI supports four languages, selectable from the dropdown in the top-right of the preview nav bar:

- English
- 中文 (Simplified Chinese) — requires `msyh.ttc` / `msyh.ttf` (Microsoft YaHei) present on the system
- Español
- Nederlands

The selected language is persisted to `dot_analyzer.cfg`.

## Architecture

Single .cpp file (~3400 lines). Sections 1-15 are preserved core logic from v7.3, sections 16-20 are the new ImGui UI layer with OpenGL3 rendering.
