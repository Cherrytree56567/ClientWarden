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
        param.blurAmount = 90;
        param.saturationAmount = 1;
        param.tintColor = D2D1::ColorF((24.f / 255.f), (24.f / 255.f), (37.f / 255.f), 1.f);
        param.fallbackColor = D2D1::ColorF((24.f / 255.f), (24.f / 255.f), (37.f / 255.f), 1.f);

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

        ImGuiIO& io = ImGui::GetIO();
        std::vector<uint8_t> fontData = storage.readBinary("fonts/Inter_24pt-Regular.ttf");
        ImFont* Inter = io.Fonts->AddFontFromMemoryTTF(fontData.data(), static_cast<int>(fontData.size()), 18.0f);
        
        std::vector<uint8_t> RobotofontData = storage.readBinary("fonts/Roboto-Regular.ttf");
        ImFont* Roboto = io.Fonts->AddFontFromMemoryTTF(RobotofontData.data(), static_cast<int>(RobotofontData.size()), 24.0f);
        
        std::vector<uint8_t> SansfontData = storage.readBinary("fonts/Roboto-Bold.ttf");
        ImFont* SansBoldSmall = io.Fonts->AddFontFromMemoryTTF(SansfontData.data(), static_cast<int>(SansfontData.size()), 36.0f);
        ImFont* SansBold = io.Fonts->AddFontFromMemoryTTF(SansfontData.data(), static_cast<int>(SansfontData.size()), 58.0f);
        io.Fonts->Build();

        ImGuiStyle& style = ImGui::GetStyle();
        style.FrameRounding = 10.0f;

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

            if (isLogin) {
                ImGuiViewport* vp = ImGui::GetMainViewport();
                ImDrawList* drawList = ImGui::GetForegroundDrawList();

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

                drawList->AddText(SansBoldSmall, 36.0f, ImVec2(width + 50.f, vp->Size.y * 0.25), IM_COL32(180, 190, 254, 255), "Welcome to");
                drawList->AddText(SansBold, 58.0f, ImVec2(width + 50.f, vp->Size.y * 0.25 + 40), IM_COL32(205, 214, 244, 255), "Clientwarden");

                ImGui::SetCursorScreenPos(ImVec2(width + 50.f, vp->Size.y * 0.25 + 117));

                ImGui::PushFont(Inter);

                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4((69.f / 255.f), (71.f / 255.f), (90.f / 255.f), 1.f));
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::SetNextItemWidth(250.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12.0f, 10.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.5f);
                ImGui::InputTextWithHint("##EmailInput", "Email", email);
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(2);

                ImGui::SetCursorScreenPos(ImVec2(width + 50.f, vp->Size.y * 0.25 + 167));

                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4((69.f / 255.f), (71.f / 255.f), (90.f / 255.f), 1.f));
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::SetNextItemWidth(250.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12.0f, 10.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.5f);
                ImGui::InputTextWithHint("##PasswordInput", "Password", password, ImGuiInputTextFlags_Password);
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(2);

                if (ImGui::IsKeyPressed(ImGuiKey_Enter)) {
                    {
                        std::lock_guard<std::mutex> lock(loginMutex);
                        loginDone = true;
                    }
                    loginCV.notify_one();
                    isLogin = false;
                }

                ImGui::SetCursorScreenPos(ImVec2(width + 50.f, vp->Size.y * 0.25 + 217));

                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4((69.f / 255.f), (71.f / 255.f), (90.f / 255.f), 1.f));
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.0f, 7.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.5f);
                if (ImGui::Button("Login")) {
                    {
                        std::lock_guard<std::mutex> lock(loginMutex);
                        loginDone = true;
                    }
                    loginCV.notify_one();
                    isLogin = false;
                }
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(3);

                ImGui::PopFont();

                ImGui::End();
            } else if (isUnlock) {
                ImGuiViewport* vp = ImGui::GetMainViewport();
                ImDrawList* drawList = ImGui::GetForegroundDrawList();

                float width = vp->Size.x * 0.22;

                ImGui::SetNextWindowPos({vp->Pos.x - 1, vp->Pos.y -1});
                ImGui::SetNextWindowSize(ImVec2(width, vp->Size.y + 2));

                ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4((17.0f / 255.0f), (17.0f / 255.0f), (27.0f / 255.0f), 1.f));
                
                ImGui::Begin("Sidebar",
                    nullptr,
                    ImGuiWindowFlags_NoDecoration |
                    ImGuiWindowFlags_NoMove |
                    ImGuiWindowFlags_NoResize |
                    ImGuiWindowFlags_NoBringToFrontOnFocus
                );

                ImGui::End();

                ImGui::PopStyleColor();

                ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4((24.f / 255.f), (24.f / 255.f), (37.f / 255.f), 1.f));

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

                drawList->AddText(SansBoldSmall, 36.0f, ImVec2(width + 50.f, vp->Size.y * 0.25), IM_COL32(180, 190, 254, 255), "Welcome to");
                drawList->AddText(SansBold, 58.0f, ImVec2(width + 50.f, vp->Size.y * 0.25 + 40), IM_COL32(205, 214, 244, 255), "Clientwarden");

                ImGui::SetCursorScreenPos(ImVec2(width + 50.f, vp->Size.y * 0.25 + 112));

                ImGui::PushFont(Inter);

                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4((69.f / 255.f), (71.f / 255.f), (90.f / 255.f), 1.f));
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::SetNextItemWidth(250.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12.0f, 10.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.5f);
                ImGui::InputTextWithHint("##PasswordInput", "Password", UnlockPassword, ImGuiInputTextFlags_Password);
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(2);

                if (ImGui::IsKeyPressed(ImGuiKey_Enter)) {
                    {
                        std::lock_guard<std::mutex> lock(unlockMutex);
                        unlockDone = true;
                    }
                    unlockCV.notify_one();
                    isUnlock = false;
                }

                ImGui::SetCursorScreenPos(ImVec2(width + 50.f, vp->Size.y * 0.25 + 162));

                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4((69.f / 255.f), (71.f / 255.f), (90.f / 255.f), 1.f));
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.0f, 7.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.5f);
                if (ImGui::Button("Unlock")) {
                    {
                        std::lock_guard<std::mutex> lock(unlockMutex);
                        unlockDone = true;
                    }
                    unlockCV.notify_one();
                    isUnlock = false;
                }
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(3);

                ImGui::PopFont();

                ImGui::End();

                ImGui::PopStyleColor();
            } else if (true) {
                ImGuiViewport* vp = ImGui::GetMainViewport();
                ImDrawList* drawList = ImGui::GetForegroundDrawList();

                float width = vp->Size.x * 0.17;

                ImGui::SetNextWindowPos({vp->Pos.x - 1, vp->Pos.y -1});
                ImGui::SetNextWindowSize(ImVec2(width, vp->Size.y + 2));

                ImGui::SetNextWindowBgAlpha(0.9f);
                
                ImGui::Begin("Sidebar",
                    nullptr,
                    ImGuiWindowFlags_NoDecoration |
                    ImGuiWindowFlags_NoMove |
                    ImGuiWindowFlags_NoResize |
                    ImGuiWindowFlags_NoBringToFrontOnFocus
                );

                ImGui::PushFont(Inter);

                drawList->AddText(SansBold, 20.0f, ImVec2(15.f, 15.f), IM_COL32(205, 214, 244, 255), name.c_str());

                ImGui::SetCursorScreenPos(ImVec2(width - 50.f, 10.f));

                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), .0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4((49.f / 255.f), (50.f / 255.f), (68.f / 255.f), 1.f));
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.0f, 7.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, .0f);
                if (ImGui::Button("˅")) {
                    {
                        std::lock_guard<std::mutex> lock(unlockMutex);
                        unlockDone = true;
                    }
                    unlockCV.notify_one();
                    isUnlock = false;
                }
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(3);

                ImGui::PopFont();

                ImGui::End();
            }

            ImGui::Render();
            ctx->OMSetRenderTargets(1, overlayRTV.GetAddressOf(), nullptr);
            const float clear[4] = {0.f, 0.f, 0.f, 0.f};
            ctx->ClearRenderTargetView(overlayRTV.Get(), clear);

            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
            overlaySwapChain->Present(1, 0);
        }
    }

    void UI::Start() {
        if (run) return;
        run = true;
        isLogin = false;
        uiThread = std::thread(&UI::Run, this);
    }

    void UI::Stop() {
        run = false;
        if (uiThread.joinable()) {
            uiThread.join();
        }
    }

    void UI::login(std::string& email, std::string& password) {
        isLogin = true;
        loginDone = false;
        this->email = &email;
        this->password = &password;

        std::unique_lock<std::mutex> lock(loginMutex);
        loginCV.wait(lock, [this] { return loginDone; });
    }

    void UI::unlock(std::string& password, std::string name) {
        isUnlock = true;
        unlockDone = false;
        this->UnlockPassword = &password;

        std::unique_lock<std::mutex> lock(unlockMutex);
        unlockCV.wait(lock, [this] { return unlockDone; });

        this->name = name;
    }
}