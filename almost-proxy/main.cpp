#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include "encryption.hpp"
#include "samp_parser.hpp"
#include "raknet/BitStream.h"
#include "raknet/DS_RangeList.h"

#pragma comment(lib, "Ws2_32.lib")

#define SAMP_MAGIC 0x504D4153

static bool isRakNetACK(const unsigned char* buf, int len)
{
    if (len < 1) return false;
    return buf[0] == 0xC0 || buf[0] == 0xA0;
}

static bool isSAMPHeader(const unsigned char* buf, int len)
{
    if (len < 4) return false;
    return (*(uint32_t*)buf) == SAMP_MAGIC;
}

static void hex_dump(const char* label, const uint8_t* data, int len)
{
    printf("%s (%d bytes):\n  ", label, len);
    for (int i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) printf("\n  ");
        printf("%02X ", data[i]);
    }
    printf("\n");
}

struct ClientInfo {
    sockaddr_in addr{};
    std::chrono::steady_clock::time_point last;
};

int main(int argc, char* argv[])
{
    if (argc < 3) {
        printf("usage: %s <remote_ip> <remote_port> [listen_ip] [listen_port]\n", argv[0]);
        return 1;
    }

    const char* remoteIp = argv[1];
    const int   remotePort = std::stoi(argv[2]);
    const char* listenIp = (argc >= 4) ? argv[3] : "0.0.0.0";
    const int   listenPort = (argc >= 5) ? std::stoi(argv[4]) : remotePort;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[ERROR] WSAStartup failed\n");
        return 1;
    }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        printf("[ERROR] socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    sockaddr_in local{};
    local.sin_family = AF_INET;
    inet_pton(AF_INET, listenIp, &local.sin_addr);
    local.sin_port = htons(listenPort);
    if (bind(s, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        printf("[ERROR] bind failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }

    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    inet_pton(AF_INET, remoteIp, &remote.sin_addr);
    remote.sin_port = htons(remotePort);

    uint32_t remoteIpBin = 0, listenIpBin = 0;
    inet_pton(AF_INET, remoteIp, &remoteIpBin);
    inet_pton(AF_INET, listenIp, &listenIpBin);
    uint16_t remotePortN = htons(remotePort);
    uint16_t listenPortN = htons(listenPort);

    printf("[INFO] Proxy: %s:%d <-> %s:%d\n\n", listenIp, listenPort, remoteIp, remotePort);

    static unsigned char buf[65536];
    static unsigned char tmp[65536];
    std::vector<ClientInfo> clients;
    sockaddr_in src{};
    int srcLen = sizeof(src);

    while (true) {
        int recvLen = recvfrom(s, (char*)buf, sizeof(buf), 0, (sockaddr*)&src, &srcLen);
        if (recvLen == SOCKET_ERROR) {
            printf("[ERROR] recvfrom failed: %d\n", WSAGetLastError());
            break;
        }

        char srcStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, srcStr, sizeof(srcStr));
        const int srcPort = ntohs(src.sin_port);

        const bool fromServer = (src.sin_addr.s_addr == remote.sin_addr.s_addr
            && src.sin_port == remote.sin_port);

        if (!fromServer) {
            printf("\n>>> C->S  %s:%d  len=%d\n", srcStr, srcPort, recvLen);

            auto now = std::chrono::steady_clock::now();
            bool found = false;
            for (auto& c : clients) {
                if (c.addr.sin_addr.s_addr == src.sin_addr.s_addr && c.addr.sin_port == src.sin_port) {
                    c.last = now; found = true; break;
                }
            }
            if (!found) {
                clients.push_back({ src, now });
                printf("[INFO] new client: %s:%d\n", srcStr, srcPort);
            }

            if (isRakNetACK(buf, recvLen)) {
                printf("[ACK] forward as-is\n");
                sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&remote, sizeof(remote));
            }
            else if (isSAMPHeader(buf, recvLen)) {
                printf("[SAMP_HDR] opcode=0x%02X\n", recvLen > 10 ? buf[10] : 0);
                memcpy(buf + 4, &remoteIpBin, 4);
                memcpy(buf + 8, &remotePortN, 2);
                sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&remote, sizeof(remote));
            }
            else {
                hex_dump("raw", buf, recvLen);
                memcpy(tmp, buf, recvLen);
                if (sampDecrypt(tmp, recvLen, listenPort, 0)) {
                    const int decrLen = recvLen - 1;
                    hex_dump("decrypted", decrBuffer, decrLen);
                    samp_parse_packet(decrBuffer, decrLen, Direction::ClientToServer,
                        static_cast<uint16_t>(srcPort));
                }
                sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&remote, sizeof(remote));
            }
        }
        else {
            printf("\n<<< S->C  %s:%d  len=%d\n", srcStr, srcPort, recvLen);

            auto now = std::chrono::steady_clock::now();
            clients.erase(std::remove_if(clients.begin(), clients.end(), [&](const ClientInfo& c) {
                return std::chrono::duration_cast<std::chrono::seconds>(now - c.last).count() > 60;
                }), clients.end());

            if (clients.empty()) {
                printf("[WARN] no clients, dropping\n");
            }
            else {
                auto it = std::max_element(clients.begin(), clients.end(), [](const ClientInfo& a, const ClientInfo& b) {
                    return a.last < b.last;
                    });

                if (isRakNetACK(buf, recvLen)) {
                    printf("[ACK] forward as-is\n");
                    sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&it->addr, sizeof(it->addr));
                }
                else if (isSAMPHeader(buf, recvLen)) {
                    printf("[SAMP_HDR] opcode=0x%02X\n", recvLen > 10 ? buf[10] : 0);
                    memcpy(buf + 4, &listenIpBin, 4);
                    memcpy(buf + 8, &listenPortN, 2);
                    sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&it->addr, sizeof(it->addr));
                }
                else {
                    hex_dump("raw", buf, recvLen);
                    memcpy(tmp, buf, recvLen);
                    if (sampDecrypt(tmp, recvLen, listenPort, 0)) {
                        const int decrLen = recvLen - 1;
                        hex_dump("decrypted", decrBuffer, decrLen);
                        samp_parse_packet(decrBuffer, decrLen, Direction::ServerToClient,
                            static_cast<uint16_t>(srcPort));
                    }
                    sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&it->addr, sizeof(it->addr));
                }
            }
        }

        printf("---\n");
        srcLen = sizeof(src);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}