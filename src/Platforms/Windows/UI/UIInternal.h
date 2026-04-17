#pragma once
#ifndef UNICODE
#define UNICODE
#endif 
#include <memory>
#include <Windows.h>
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")
#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>
#include <backends/imgui_impl_win32.h>
#include <backends/imgui_impl_dx11.h>
#include "AcrylicCompositor.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

bool active;
std::unique_ptr<AcrylicCompositor> compositor{nullptr};

struct ACCENT_POLICY {
    int AccentState;
    int AccentFlags;
    int GradientColor;
    int AnimationId;
};

struct WINDOWCOMPOSITIONATTRIBDATA {
    int Attrib;
    PVOID pvData;
    SIZE_T cbData;
};

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam)) {
        return true;
    }

    if (compositor)
    {
        if (uMsg == WM_ACTIVATE)
        {
            if (LOWORD(wParam) == WA_ACTIVE || LOWORD(wParam)==WA_CLICKACTIVE)
            {
                active = true;
            }
            else if (LOWORD(wParam) == WA_INACTIVE)
            {
                active = false;
            }
        }
        compositor->Sync(hwnd, uMsg, wParam, lParam,active);
    }

    switch (uMsg)
    {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}