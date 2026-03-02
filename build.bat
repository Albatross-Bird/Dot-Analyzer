@echo off
echo === Building Dot Analyzer v8.0 (ImGui + OpenGL3) ===
echo.

REM --- Check for ImGui files ---
if not exist "imgui\imgui.h" (
    echo ERROR: imgui\imgui.h not found.
    echo.
    echo Download ImGui from https://github.com/ocornut/imgui
    echo Expected folder layout:
    echo   imgui\
    echo     imgui.h, imgui.cpp, imgui_draw.cpp, imgui_tables.cpp, imgui_widgets.cpp
    echo     backends\
    echo       imgui_impl_win32.h, imgui_impl_win32.cpp
    echo       imgui_impl_opengl3.h, imgui_impl_opengl3.cpp
    echo.
    pause
    exit /b 1
)

echo [1/3] Compiling resource file...
if exist dot_analyzer.rc (
    windres dot_analyzer.rc -o dot_analyzer_res.o
    if errorlevel 1 (
        echo WARNING: Resource compilation failed, building without icon.
        set "RES_OBJ="
    ) else (
        set "RES_OBJ=dot_analyzer_res.o"
    )
) else (
    echo       No .rc file found, building without icon.
    set "RES_OBJ="
)

echo [2/3] Compiling source code...
g++ dot_analyzer_v8.1.6.cpp %RES_OBJ% ^
    imgui\imgui.cpp ^
    imgui\imgui_draw.cpp ^
    imgui\imgui_tables.cpp ^
    imgui\imgui_widgets.cpp ^
    imgui\backends\imgui_impl_win32.cpp ^
    imgui\backends\imgui_impl_opengl3.cpp ^
    -o "Dot Analyzer.exe" ^
    -I./imgui -I./imgui/backends ^
    -lgdi32 -lopengl32 -ldwmapi -lcomdlg32 -lcomctl32 -lole32 ^
    -lshell32 -lshlwapi -lws2_32 ^
    -mwindows -O2 -DUNICODE -D_UNICODE
if errorlevel 1 (
    echo ERROR: Compilation failed.
    pause
    exit /b 1
)

echo [3/3] Cleaning up...
if exist dot_analyzer_res.o del dot_analyzer_res.o 2>nul

echo.
echo === Build successful: "Dot Analyzer.exe" ===
echo.
echo NOTE: Record Mode requires Npcap to be installed (https://npcap.com)
echo       Analysis features work without Npcap.
echo.
pause
