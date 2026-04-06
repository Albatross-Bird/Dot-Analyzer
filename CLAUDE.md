# Dot Analyzer — Claude Code Context

## Project overview

Single-exe Windows desktop tool that analyzes PGM images of dispensed fluid dots on a substrate. Measures diameter, circularity, XY grid offset, and flags missed/merged dots across image batches. Includes live GVSP packet capture from Basler cameras via Npcap for a Record Mode that auto-captures when the camera image stabilizes.

UI is built with Dear ImGui + OpenGL3 rendered into a native Win32 window.

## Source layout

```
dot_analyzer_v8.2.6.cpp   — entire application (current version)
dot_analyzer.cfg           — persisted settings (key=value, written by save_config)
build.bat                  — one-liner g++ build command (always points to current version)
versions/                  — archived prior versions (V7.3–V8.2.5), read-only reference
imgui/                     — Dear ImGui source (not committed, user places manually)
```

There are no header files, no separate translation units, no CMake/Makefile — just one `.cpp` and `build.bat`.

## Version workflow

When creating a new version (e.g. v8.2.3 → v8.2.4):
1. `cp dot_analyzer_vX.Y.Z.cpp "versions/dot_analyzer VX.Y.Z.cpp"` — archive current
2. `cp dot_analyzer_vX.Y.Z.cpp dot_analyzer_vX.Y.W.cpp` — create new version
3. Update the version string in the file header comment
4. Update `build.bat` to reference the new filename
5. Make code changes
6. windres + g++ compile, confirm BUILD OK, remove .o

## Section map (search by comment banner)

| Section | Content |
|---------|---------|
| 1–15    | Core analysis logic (preserved from v7.3) |
| 3b      | Internationalization — `lang_strings_t` struct + 4 language instances |
| 12      | Config — `save_config()` / `load_config()` (key=value file) |
| 13      | Record mode helpers — `start_recording()`, `stop_recording()`, live preview |
| 16–20   | ImGui UI layer — `render_ui()` is the single render function called each frame |

## Key globals

| Variable | Type | Purpose |
|----------|------|---------|
| `L` | `const lang_strings_t *` | Active language; all UI uses `L->field` |
| `g_lang` | `int` | Language index (0=EN,1=ZH,2=ES,3=NL) |
| `g_threshold`, `g_auto_thresh` | `int` | Binarization threshold |
| `g_stable_sec_buf`, `g_mad_thresh_buf` | `char[32]` | Text buffers for stable-time and MAD inputs |
| `g_rec_stable_sec`, `g_rec_mad_thresh` | `double` | Parsed at recording start from the buffers above |
| `g_rec_state` | enum | `REC_IDLE` / `REC_RUNNING` |
| `g_live_running` | `int` | 1 while live preview stream thread is active |
| `g_stitch_mode` | `int` | Whether stitch assembly is enabled |

## Config persistence pattern

`save_config()` writes all persisted state to `dot_analyzer.cfg` as `key=value\n` lines.
`load_config()` reads them back with manual `strncmp` key matching.

**To add a new persisted value:**
1. Add `fprintf(f, "key=%s\n", buf)` (or `%d` for ints) inside `save_config`.
2. Add a matching `else if (kl == N && strncmp(line, "key", N) == 0)` branch in `load_config` where `N` is `strlen("key")`. Validate before assigning (see existing branches for range checks).

`save_config` is called on: "Process All Images" click, language change, window close (`WM_DESTROY`).

## Internationalization pattern

All UI-visible strings go through the global `L` pointer (`lang_strings_t`).

**To add a new translatable string:**
1. Add `const char *field_name;` to `lang_strings_t` (Section 3b, ~line 321).
2. Append a value to each of the four static instances in order: `lang_en`, `lang_zh`, `lang_es`, `lang_nl` (positional initializers — order must match struct field order).
3. Replace the hardcoded literal in the UI with `L->field_name`.
4. Chinese strings must be UTF-8 encoded as hex escape sequences (`\xNN`); the font atlas loads Microsoft YaHei (`msyh.ttc`) at startup for CJK glyph coverage.

## Build

```bat
g++ dot_analyzer_v8.2.6.cpp imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp imgui/backends/imgui_impl_win32.cpp imgui/backends/imgui_impl_opengl3.cpp -o "Dot Analyzer.exe" -I./imgui -I./imgui/backends -lgdi32 -lopengl32 -ldwmapi -lcomdlg32 -lcomctl32 -lole32 -lshell32 -lshlwapi -lws2_32 -mwindows -O2 -DUNICODE -D_UNICODE
```

Requires MinGW-w64. Npcap SDK headers needed for Record Mode (`-lwpcap`); if absent, Record Mode compiles but capture is a no-op.

## Things to watch out for

- **Single-file, positional struct init**: `lang_strings_t` instances use positional C initializers. Adding a field anywhere other than the end will silently misalign every language value below it.
- **`L->` vs hardcoded literals**: Any `ImGui::Text("...")`, `ImGui::Button("...")`, `ImGui::Checkbox("...", ...)`, or `ImGui::InputText("...", ...)` with a string literal is untranslated. Always route new UI strings through `L->`.
- **`ImGui::Text` format safety**: Use `ImGui::Text("%s", L->field)` not `ImGui::Text(L->field)` to avoid format-string issues when the value comes through a pointer.
- **Config key length**: The `kl == N` guard in `load_config` must exactly equal `strlen("key")`. Getting this wrong silently skips the key on load.
- **Thread safety**: Recording and live preview run on background threads. The render thread reads `g_rec_status`, `g_mad_current`, and the preview texture. Writes from worker threads to these shared values are not mutex-guarded — keep that in mind for any new shared state.
