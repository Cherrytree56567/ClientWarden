#include "UI.h"
#include "UIInternal.h"

namespace ClientWarden::UI {
    UI::UI() : storage("") {
        logger = spdlog::stdout_color_mt("ClientWarden::Vault::SSHKeyItem");
    }

    void UI::Run() {
        LPCSTR CLASS_NAME = "ClientWarden.UI";
        
        WNDCLASS wc = {};

        HINSTANCE hInstance = GetModuleHandle(nullptr);
        int nCmdShow = SW_SHOW;

        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = CLASS_NAME;

        RegisterClass(&wc);

        HWND hwnd = CreateWindowEx(
            WS_EX_NOREDIRECTIONBITMAP,
            CLASS_NAME,
            "ClientWarden",
            WS_OVERLAPPEDWINDOW,

            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,

            NULL,
            NULL,
            hInstance,
            NULL
        );

        if (hwnd == NULL) {
            logger->info("Failed to Create Window");
            return;
        }

        ShowWindow(hwnd, nCmdShow);

        compositor.reset(new AcrylicCompositor(hwnd));

        AcrylicCompositor::AcrylicEffectParameter param;
        param.blurAmount = 40;
        param.saturationAmount = 1;
        param.tintColor = D2D1::ColorF((2.0f / 255.0f), (6.0f / 255.0f), (24.0f / 255.0f), 0.87f);
        param.fallbackColor = D2D1::ColorF((2.0f / 255.0f), (6.0f / 255.0f), (24.0f / 255.0f), 0.87f);

        compositor->SetAcrylicEffect(hwnd, AcrylicCompositor::BACKDROP_SOURCE_HOSTBACKDROP, param);

        ComPtr<IDXGISwapChain1> overlaySwapChain;
        ComPtr<ID3D11RenderTargetView> overlayRTV;

        compositor->CreateOverlayLayer(&overlaySwapChain);

        ComPtr<ID3D11Texture2D> backBuf;
        overlaySwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuf));
        compositor->GetD3DDevice()->CreateRenderTargetView(backBuf.Get(), nullptr, &overlayRTV);

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(compositor->GetD3DDevice(), compositor->GetD3DContext());

        run = true;

        MSG msg = {};
        while (run) {
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) {
                    run = false;
                }

                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }

            auto* ctx = compositor->GetD3DContext();

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            ImGuiViewport* vp = ImGui::GetMainViewport();
            ImGuiIO& io = ImGui::GetIO();

            std::vector<uint8_t> fontData = storage.readBinary("fonts/Inter_24pt-Regular.ttf");

            ImFont* myFont = io.Fonts->AddFontFromMemoryTTF(fontData.data(), static_cast<int>(fontData.size()), 24.0f);

            float width = vp->Size.x * 0.22;

            ImGui::SetNextWindowPos({vp->Pos.x - 1, vp->Pos.y -1});
            ImGui::SetNextWindowSize(ImVec2(width, vp->Size.y + 2));

            ImGui::SetNextWindowBgAlpha(0.5f);
            
            ImGui::Begin("Sidebar",
                nullptr,
                ImGuiWindowFlags_NoDecoration |
                ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoBringToFrontOnFocus
            );

            ImGui::End();

            ImGui::SetNextWindowPos(ImVec2(width, 0));
            ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

            ImGui::Begin("ClientWarden",
                nullptr,
                ImGuiWindowFlags_NoDecoration |
                ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoBringToFrontOnFocus |
                ImGuiWindowFlags_NoBackground 
            );

            ImGui::Text("Client Warden");

            std::string email;

            ImGui::SetNextItemWidth(250.0f);
            ImGui::InputTextWithHint("##EmailInput", "Enter your email...", &email);

            ImGui::End();

            ImGui::Render();
            ctx->OMSetRenderTargets(1, overlayRTV.GetAddressOf(), nullptr);
            const float clear[4] = {0.f, 0.f, 0.f, 0.f};
            ctx->ClearRenderTargetView(overlayRTV.Get(), clear);

            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
            overlaySwapChain->Present(1, 0);
        }
    }
}