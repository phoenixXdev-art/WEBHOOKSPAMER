#include <windows.h>
#include <commctrl.h>
#include <Richedit.h>
#include <winhttp.h>
#include <shellapi.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define WM_APP_LOG (WM_APP + 1)
#define WM_APP_STOP (WM_APP + 2)
#define WM_APP_NAME_FETCHED (WM_APP + 3)

HWND hUrlBox, hNameBox, hMsgBox, hLimitBox, hStartBtn, hStopBtn, hLogBox, hMentionBtn, hImageBtn, hFetchBtn;
std::atomic<bool> isSpamming(false);
std::atomic<int> globalCount(0);
std::atomic<int> targetLimit(1000);
std::vector<std::thread> workers;
std::mutex sendMutex;

const int NUM_THREADS = 10;
std::wstring g_imagePath = L"";

void LogMessage(HWND hwnd, const std::wstring& msg, COLORREF color = RGB(0, 255, 0)) {
    std::wstring* pMsg = new std::wstring(msg);
    WPARAM wParam = (WPARAM)color;
    LPARAM lParam = (LPARAM)pMsg;
    PostMessage(hwnd, WM_APP_LOG, wParam, lParam);
}

std::vector<char> ReadFileBytes(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    if (file.read(buffer.data(), size)) return buffer;
    return {};
}

bool SendWebhook(const std::wstring& url, const std::wstring& msg, const std::wstring& name, const std::wstring& imgPath, int& rateLimitWaitMs) {
    rateLimitWaitMs = 0;
    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwSchemeLength = (DWORD)-1;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) return false;

    std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), urlComp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::vector<char> payload;
    std::wstring headers;

    std::string msgStr(msg.begin(), msg.end());
    std::string nameStr(name.begin(), name.end());

    if (!imgPath.empty()) {
        std::vector<char> fileData = ReadFileBytes(imgPath);
        if (fileData.empty()) {
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
            return false;
        }

        std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        headers = L"Content-Type: multipart/form-data; boundary=" + std::wstring(boundary.begin(), boundary.end()) + L"\r\n";

        std::string jsonPart = "{\"content\":\"" + msgStr + "\",\"username\":\"" + nameStr + "\"}";
        std::string body = "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"payload_json\"\r\n\r\n";
        body += jsonPart + "\r\n";
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"file\"; filename=\"image.png\"\r\n";
        body += "Content-Type: image/png\r\n\r\n";

        payload.insert(payload.end(), body.begin(), body.end());
        payload.insert(payload.end(), fileData.begin(), fileData.end());

        std::string endBoundary = "\r\n--" + boundary + "--\r\n";
        payload.insert(payload.end(), endBoundary.begin(), endBoundary.end());
    }
    else {
        headers = L"Content-Type: application/json\r\n";
        std::string json = "{\"content\":\"" + msgStr + "\",\"username\":\"" + nameStr + "\"}";
        payload.assign(json.begin(), json.end());
    }

    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1L,
        (LPVOID)payload.data(), (DWORD)payload.size(), (DWORD)payload.size(), 0);

    DWORD statusCode = 0;
    DWORD dwSize = sizeof(statusCode);
    bool success = false;

    if (bResults && WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

        if (statusCode == 429) {
            DWORD bytesRead = 0;
            char buffer[4096] = { 0 };
            WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead);
            std::string responseStr(buffer);

            size_t pos = responseStr.find("\"retry_after\":");
            if (pos != std::string::npos) {
                size_t endPos = responseStr.find_first_of(",}", pos + 14);
                if (endPos != std::string::npos) {
                    std::string valStr = responseStr.substr(pos + 14, endPos - (pos + 14));
                    try { rateLimitWaitMs = (int)(std::stod(valStr) * 1000) + 100; }
                    catch (...) { rateLimitWaitMs = 2000; }
                }
            }
            else { rateLimitWaitMs = 2000; }
        }
        else if (statusCode >= 200 && statusCode < 300) {
            success = true;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return success;
}

void FetchWebhookName(HWND hwnd, std::wstring url) {
    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwSchemeLength = (DWORD)-1;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) return;

    std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), urlComp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD bytesRead = 0;
        char buffer[4096] = { 0 };
        WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead);
        std::string responseStr(buffer);

        size_t pos = responseStr.find("\"name\":\"");
        if (pos != std::string::npos) {
            size_t endPos = responseStr.find("\"", pos + 8);
            if (endPos != std::string::npos) {
                std::string nameStr = responseStr.substr(pos + 8, endPos - (pos + 8));
                std::wstring wName(nameStr.begin(), nameStr.end());
                PostMessage(hwnd, WM_APP_NAME_FETCHED, 0, (LPARAM)new std::wstring(wName));
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void SpamWorker(HWND hwnd, int threadId, std::wstring url, std::wstring msg, std::wstring name, std::wstring imgPath) {
    while (isSpamming) {
        int currentCount;
        if ((currentCount = ++globalCount) > targetLimit) {
            isSpamming = false;
            PostMessage(hwnd, WM_APP_STOP, 0, 0);
            break;
        }

        int retryWait = 0;
        bool success;

        {
            std::lock_guard<std::mutex> lock(sendMutex);
            if (!isSpamming) break;
            success = SendWebhook(url, msg, name, imgPath, retryWait);
        }

        std::wstring logMsg = L"[Thread " + std::to_wstring(threadId) + L"] Sent #" + std::to_wstring(currentCount) +
            (success ? L" -> OK" : (retryWait > 0 ? L" -> RATE LIMITED, WAITING" : L" -> FAILED"));

        LogMessage(hwnd, logMsg, success ? RGB(0, 255, 0) : RGB(255, 50, 50));

        int waitTime = (retryWait > 0) ? retryWait : 400;
        for (int i = 0; i < waitTime && isSpamming; i += 10) Sleep(10);
    }
}

void StartSpam(HWND hwnd) {
    if (isSpamming) return;

    wchar_t urlBuf[1024], msgBuf[4096], limitBuf[32], nameBuf[128];
    GetWindowTextW(hUrlBox, urlBuf, 1024);
    GetWindowTextW(hMsgBox, msgBuf, 4096);
    GetWindowTextW(hLimitBox, limitBuf, 32);
    GetWindowTextW(hNameBox, nameBuf, 128);

    std::wstring url = urlBuf;
    std::wstring msg = msgBuf;
    std::wstring name = nameBuf;
    int limit = _wtoi(limitBuf);

    if (limit < 1) limit = 1000;
    targetLimit = limit;
    globalCount = 0;

    if (url.empty() || msg.empty()) {
        LogMessage(hwnd, L"[-] URL and Message cannot be empty.", RGB(255, 0, 0));
        return;
    }

    isSpamming = true;
    EnableWindow(hStartBtn, FALSE);
    EnableWindow(hStopBtn, TRUE);

    LogMessage(hwnd, L"[*] Starting spam with 10 threads. Limit: " + std::to_wstring(limit) + L" Name: " + name, RGB(0, 255, 255));
    if (!g_imagePath.empty()) LogMessage(hwnd, L"[*] Attached Image: " + g_imagePath, RGB(0, 255, 255));

    for (int i = 1; i <= NUM_THREADS; i++) {
        workers.push_back(std::thread(SpamWorker, hwnd, i, url, msg, name, g_imagePath));
    }
}

void StopSpam(HWND hwnd) {
    if (!isSpamming && workers.empty()) return;
    isSpamming = false;
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }
    workers.clear();
    EnableWindow(hStartBtn, TRUE);
    EnableWindow(hStopBtn, FALSE);
    LogMessage(hwnd, L"[*] Stopped. Total sent: " + std::to_wstring(globalCount.load()), RGB(255, 165, 0));
}

void ChooseImage(HWND hwnd) {
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Image Files\0*.png;*.jpg;*.jpeg;*.gif;*.webp\0All Files\0*.*\0";
    ofn.lpstrFile = new wchar_t[MAX_PATH];
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        g_imagePath = ofn.lpstrFile;
        LogMessage(hwnd, L"[*] Selected Image to upload: " + g_imagePath, RGB(0, 255, 255));
        SetWindowTextW(hImageBtn, L"IMAGE READY");
    }
    delete[] ofn.lpstrFile;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
        HFONT hBtnFont = CreateFontW(15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        CreateWindowExW(0, L"STATIC", L"Webhook URL:", WS_CHILD | WS_VISIBLE, 20, 20, 110, 20, hwnd, NULL, NULL, NULL);
        hUrlBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            130, 15, 520, 25, hwnd, (HMENU)1, NULL, NULL);

        hFetchBtn = CreateWindowExW(0, L"BUTTON", L"FETCH NAME", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 55, 110, 28, hwnd, (HMENU)15, NULL, NULL);

        CreateWindowExW(0, L"STATIC", L"Webhook Name:", WS_CHILD | WS_VISIBLE, 140, 60, 100, 20, hwnd, NULL, NULL, NULL);
        hNameBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            240, 55, 410, 25, hwnd, (HMENU)16, NULL, NULL);

        CreateWindowExW(0, L"STATIC", L"Message:", WS_CHILD | WS_VISIBLE, 20, 95, 100, 20, hwnd, NULL, NULL, NULL);
        hMsgBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
            20, 115, 630, 60, hwnd, (HMENU)2, NULL, NULL);

        hMentionBtn = CreateWindowExW(0, L"BUTTON", L"@everyone", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 185, 90, 28, hwnd, (HMENU)8, NULL, NULL);

        hImageBtn = CreateWindowExW(0, L"BUTTON", L"CHOOSE IMAGE", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            120, 185, 120, 28, hwnd, (HMENU)9, NULL, NULL);

        CreateWindowExW(0, L"STATIC", L"Limit:", WS_CHILD | WS_VISIBLE, 260, 190, 40, 20, hwnd, NULL, NULL, NULL);
        hLimitBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"1000", WS_CHILD | WS_VISIBLE | ES_NUMBER,
            300, 185, 60, 25, hwnd, (HMENU)7, NULL, NULL);

        hStartBtn = CreateWindowExW(0, L"BUTTON", L"START SPAM", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            380, 185, 130, 28, hwnd, (HMENU)4, NULL, NULL);
        hStopBtn = CreateWindowExW(0, L"BUTTON", L"STOP", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            520, 185, 130, 28, hwnd, (HMENU)5, NULL, NULL);
        EnableWindow(hStopBtn, FALSE);

        hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            20, 230, 630, 180, hwnd, (HMENU)6, NULL, NULL);
        SendMessageW(hLogBox, EM_SETBKGNDCOLOR, 0, (LPARAM)RGB(15, 15, 15));

        // Footer label
        HWND hFooter = CreateWindowExW(0, L"STATIC", L"Developed by PHOENIX", WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 420, 630, 20, hwnd, NULL, NULL, NULL);
        HFONT hFooterFont = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        SendMessageW(hFooter, WM_SETFONT, (WPARAM)hFooterFont, TRUE);

        EnumChildWindows(hwnd, [](HWND child, LPARAM lParam) -> BOOL {
            SendMessageW(child, WM_SETFONT, (WPARAM)lParam, TRUE);
            return TRUE;
            }, (LPARAM)hFont);

        SendMessageW(hStartBtn, WM_SETFONT, (WPARAM)hBtnFont, TRUE);
        SendMessageW(hStopBtn, WM_SETFONT, (WPARAM)hBtnFont, TRUE);
        SendMessageW(hMentionBtn, WM_SETFONT, (WPARAM)hBtnFont, TRUE);
        SendMessageW(hImageBtn, WM_SETFONT, (WPARAM)hBtnFont, TRUE);
        SendMessageW(hFetchBtn, WM_SETFONT, (WPARAM)hBtnFont, TRUE);
        SendMessageW(hUrlBox, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hNameBox, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hMsgBox, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hLimitBox, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hFooter, WM_SETFONT, (WPARAM)hFooterFont, TRUE);

        DragAcceptFiles(hwnd, TRUE);
        break;
    }
    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wParam;
        UINT fileCount = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);
        for (UINT i = 0; i < fileCount; i++) {
            wchar_t filePath[MAX_PATH];
            DragQueryFileW(hDrop, i, filePath, MAX_PATH);
            g_imagePath = filePath;
            LogMessage(hwnd, L"[*] Dropped Image to upload: " + g_imagePath, RGB(0, 255, 255));
            SetWindowTextW(hImageBtn, L"IMAGE READY");
        }
        DragFinish(hDrop);
        break;
    }
    case WM_APP_LOG: {
        COLORREF color = (COLORREF)wParam;
        std::wstring* pMsg = (std::wstring*)lParam;
        int len = GetWindowTextLengthW(hLogBox);
        SendMessageW(hLogBox, EM_SETSEL, (WPARAM)len, (LPARAM)len);

        CHARFORMAT2W cf;
        ZeroMemory(&cf, sizeof(cf));
        cf.cbSize = sizeof(cf);
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = color;
        SendMessageW(hLogBox, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

        std::wstring formatted = *pMsg + L"\r\n";
        SendMessageW(hLogBox, EM_REPLACESEL, FALSE, (LPARAM)formatted.c_str());
        SendMessageW(hLogBox, EM_SCROLLCARET, 0, 0);
        delete pMsg;
        break;
    }
    case WM_APP_NAME_FETCHED: {
        std::wstring* pName = (std::wstring*)lParam;
        SetWindowTextW(hNameBox, pName->c_str());
        LogMessage(hwnd, L"[*] Successfully fetched webhook name: " + *pName, RGB(0, 255, 255));
        delete pName;
        EnableWindow(hFetchBtn, TRUE);
        break;
    }
    case WM_APP_STOP: {
        StopSpam(hwnd);
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 4) StartSpam(hwnd);
        else if (LOWORD(wParam) == 5) StopSpam(hwnd);
        else if (LOWORD(wParam) == 8) {
            SendMessageW(hMsgBox, EM_REPLACESEL, TRUE, (LPARAM)L"@everyone ");
            SetFocus(hMsgBox);
        }
        else if (LOWORD(wParam) == 9) {
            ChooseImage(hwnd);
        }
        else if (LOWORD(wParam) == 15) {
            wchar_t urlBuf[1024];
            GetWindowTextW(hUrlBox, urlBuf, 1024);
            if (wcslen(urlBuf) > 10) {
                EnableWindow(hFetchBtn, FALSE);
                LogMessage(hwnd, L"[*] Fetching webhook name from Discord...", RGB(255, 165, 0));
                std::thread(FetchWebhookName, hwnd, std::wstring(urlBuf)).detach();
            }
            else {
                LogMessage(hwnd, L"[-] Please paste a valid webhook URL first.", RGB(255, 0, 0));
            }
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        if (hCtrl == GetWindow(hwnd, GW_CHILD) || GetWindowTextLengthW(hCtrl) == 18) {
            SetTextColor(hdc, RGB(255, 165, 0)); // Orange color for PHOENIX footer
        }
        else {
            SetTextColor(hdc, RGB(200, 200, 200));
        }
        SetBkColor(hdc, RGB(30, 30, 30));
        static HBRUSH hBrush = CreateSolidBrush(RGB(30, 30, 30));
        return (LRESULT)hBrush;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(0, 255, 0));
        SetBkColor(hdc, RGB(20, 20, 20));
        static HBRUSH hBrush = CreateSolidBrush(RGB(20, 20, 20));
        return (LRESULT)hBrush;
    }
    case WM_DESTROY: {
        StopSpam(hwnd);
        PostQuitMessage(0);
        break;
    }
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    LoadLibraryW(L"Msftedit.dll");

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszClassName = L"SpamClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, L"SpamClass", L"Discord Webhook Spammer - by PHOENIX",
        WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 690, 500,
        NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
