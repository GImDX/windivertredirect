#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <time.h>
#include "../include/windivert.h"

#pragma comment(lib, "Ws2_32.lib")

#define MAX_IPS 16  // 最多支持10个目标IP
#define FILTER_SIZE 512  // 过滤字符串最大长度

// #define _TARGET_IP   "43.134.68.141" exclude ip
// #define TARGET_PORT "10250"          target port
// #define REDIRECT_IP "192.168.8.114"  proxy ip
// #define REDIRECT_PORT "34010"        proxy port
void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

int main(int argc, char *argv[]) {
    // 确保有足够的输入参数
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <_TARGET_IP> <TARGET_PORT> <REDIRECT_IP> <REDIRECT_PORT>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // 读取输入参数
    char *_TARGET_IP = argv[1];
    int TARGET_PORT = atoi(argv[2]);
    char *REDIRECT_IP = argv[3];
    int REDIRECT_PORT = atoi(argv[4]);

    HANDLE handle;
    WINDIVERT_ADDRESS addr;
    char packet[1500];
    UINT packet_len;

    char time_str[20];  // 分配存储空间

    // 构造 WinDivert 过滤规则
    char filter[256];
    snprintf(filter, sizeof(filter),
         "ip.DstAddr != %s and ip.DstAddr != %s and (tcp.DstPort == %d or tcp.SrcPort == %d)",
         _TARGET_IP, REDIRECT_IP, TARGET_PORT, REDIRECT_PORT);
    printf("WinDivert Filter: %s\n", filter);

    // 打开 WinDivert
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 30000, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("Starting packet capture...\n");

    while (1) {
        // 捕获数据包
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) {
            printf("Failed to capture packet (%d)\n", GetLastError());
            continue;
        }

        PWINDIVERT_IPHDR ip_header = NULL;
        PWINDIVERT_TCPHDR tcp_header = NULL;

        // 解析数据包（只解析 TCP/IP）
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, NULL, &tcp_header, NULL, NULL, NULL, NULL, NULL);
        
        struct in_addr DstAddr, SrcAddr;
        DstAddr.s_addr = ip_header->DstAddr;
        SrcAddr.s_addr = ip_header->SrcAddr;

        get_timestamp(time_str, sizeof(time_str));
        printf("%s\n", time_str);
        printf("%-15s: SrcAddr=%s SrcPort=%u, DstAddr=%s, DstPort=%u\n", "Original Packet",
               strdup(inet_ntoa(SrcAddr)), WinDivertHelperNtohs(tcp_header->SrcPort),
               strdup(inet_ntoa(DstAddr)), WinDivertHelperNtohs(tcp_header->DstPort));

        if (addr.Outbound) {
            if (tcp_header->DstPort == WinDivertHelperHtons(TARGET_PORT)) {
                // 处理 client->proxy
                UINT32 dst_addr = ip_header->DstAddr;
                tcp_header->DstPort = WinDivertHelperHtons(REDIRECT_PORT);
                ip_header->DstAddr = inet_addr(REDIRECT_IP);
                ip_header->SrcAddr = dst_addr;
                
                addr.Outbound = FALSE;

                DstAddr.s_addr = ip_header->DstAddr;
                SrcAddr.s_addr = ip_header->SrcAddr;
                printf("Client->Proxy\n");
                printf("%-15s: DstAddr->%s, DstPort->%u, SrcAddr->%s\n","Divert",
                       strdup(inet_ntoa(DstAddr)), WinDivertHelperNtohs(tcp_header->DstPort), strdup(inet_ntoa(SrcAddr)));
            } else if (tcp_header->SrcPort == WinDivertHelperHtons(REDIRECT_PORT)) {
                // 处理 proxy->client
                UINT32 dst_addr = ip_header->DstAddr;
                tcp_header->SrcPort = WinDivertHelperHtons(TARGET_PORT);
                ip_header->DstAddr = inet_addr(REDIRECT_IP);
                ip_header->SrcAddr = dst_addr;
                
                addr.Outbound = FALSE;

                DstAddr.s_addr = ip_header->DstAddr;
                SrcAddr.s_addr = ip_header->SrcAddr;
                printf("Proxy->Client\n");
                printf("%-15s: SrcAddr->%s, SrcPort->%u, DstAddr->%s\n","Divert",
                       strdup(inet_ntoa(SrcAddr)), WinDivertHelperNtohs(tcp_header->SrcPort), strdup(inet_ntoa(DstAddr)));
            } else {
                printf("error: Unknown packet\n");
                continue;
            }

            // 重新计算校验和
            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);

            UINT sendLen = 0;
            // 重新注入修改后的数据包
            if (!WinDivertSend(handle, packet, packet_len, &sendLen, &addr)) {
                printf("Failed to send packet (%d)\n", GetLastError());
                continue;
            }
            printf("Divert packet reinjected...\n\n");
        }
    }

    WinDivertClose(handle);
    return 0;
}
