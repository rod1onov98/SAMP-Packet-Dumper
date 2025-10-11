#include <iostream>
#include <winsock2.h>
#include <string>
#include <cstring>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

unsigned char decrBuffer[4092];

unsigned char sampDecrTable[256] =
{
    0xB4, 0x62, 0x07, 0xE5, 0x9D, 0xAF, 0x63, 0xDD, 0xE3, 0xD0, 0xCC, 0xFE, 0xDC, 0xDB, 0x6B, 0x2E,
    0x6A, 0x40, 0xAB, 0x47, 0xC9, 0xD1, 0x53, 0xD5, 0x20, 0x91, 0xA5, 0x0E, 0x4A, 0xDF, 0x18, 0x89,
    0xFD, 0x6F, 0x25, 0x12, 0xB7, 0x13, 0x77, 0x00, 0x65, 0x36, 0x6D, 0x49, 0xEC, 0x57, 0x2A, 0xA9,
    0x11, 0x5F, 0xFA, 0x78, 0x95, 0xA4, 0xBD, 0x1E, 0xD9, 0x79, 0x44, 0xCD, 0xDE, 0x81, 0xEB, 0x09,
    0x3E, 0xF6, 0xEE, 0xDA, 0x7F, 0xA3, 0x1A, 0xA7, 0x2D, 0xA6, 0xAD, 0xC1, 0x46, 0x93, 0xD2, 0x1B,
    0x9C, 0xAA, 0xD7, 0x4E, 0x4B, 0x4D, 0x4C, 0xF3, 0xB8, 0x34, 0xC0, 0xCA, 0x88, 0xF4, 0x94, 0xCB,
    0x04, 0x39, 0x30, 0x82, 0xD6, 0x73, 0xB0, 0xBF, 0x22, 0x01, 0x41, 0x6E, 0x48, 0x2C, 0xA8, 0x75,
    0xB1, 0x0A, 0xAE, 0x9F, 0x27, 0x80, 0x10, 0xCE, 0xF0, 0x29, 0x28, 0x85, 0x0D, 0x05, 0xF7, 0x35,
    0xBB, 0xBC, 0x15, 0x06, 0xF5, 0x60, 0x71, 0x03, 0x1F, 0xEA, 0x5A, 0x33, 0x92, 0x8D, 0xE7, 0x90,
    0x5B, 0xE9, 0xCF, 0x9E, 0xD3, 0x5D, 0xED, 0x31, 0x1C, 0x0B, 0x52, 0x16, 0x51, 0x0F, 0x86, 0xC5,
    0x68, 0x9B, 0x21, 0x0C, 0x8B, 0x42, 0x87, 0xFF, 0x4F, 0xBE, 0xC8, 0xE8, 0xC7, 0xD4, 0x7A, 0xE0,
    0x55, 0x2F, 0x8A, 0x8E, 0xBA, 0x98, 0x37, 0xE4, 0xB2, 0x38, 0xA1, 0xB6, 0x32, 0x83, 0x3A, 0x7B,
    0x84, 0x3C, 0x61, 0xFB, 0x8C, 0x14, 0x3D, 0x43, 0x3B, 0x1D, 0xC3, 0xA2, 0x96, 0xB3, 0xF8, 0xC4,
    0xF2, 0x26, 0x2B, 0xD8, 0x7C, 0xFC, 0x23, 0x24, 0x66, 0xEF, 0x69, 0x64, 0x50, 0x54, 0x59, 0xF1,
    0xA0, 0x74, 0xAC, 0xC6, 0x7D, 0xB5, 0xE6, 0xE2, 0xC2, 0x7E, 0x67, 0x17, 0x5E, 0xE1, 0xB9, 0x3F,
    0x6C, 0x70, 0x08, 0x99, 0x45, 0x56, 0x76, 0xF9, 0x9A, 0x97, 0x19, 0x72, 0x5C, 0x02, 0x8F, 0x58
};

void samp_decrypt(unsigned char* buf, int len, int port, int unk)
{
    unsigned char bChecksumEncr = buf[0];

    len--;
    memcpy(decrBuffer, buf + 1, len);

    unsigned char bPort = port ^ 0xCC;
    for (int i = 0; i < len; i++)
    {
        if (!unk)
        {
            decrBuffer[i] = unk ^ decrBuffer[i];
            unk++;
        }
        else
        {
            decrBuffer[i] = bPort ^ decrBuffer[i];
            unk--;
        }

        decrBuffer[i] = sampDecrTable[decrBuffer[i]];
    }

    unsigned char bChecksum = 0;
    for (int i = 0; i < len; i++)
    {
        unsigned char bData = decrBuffer[i];
        bChecksum ^= (bData & 0xAA);
    }

    if (bChecksum != bChecksumEncr)
        printf("[WARNING] Invalid checksum: bChecksum %d != bChecksumEncr %d\n", bChecksum, bChecksumEncr);
}

void pkt_dump(const unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (i % 16 == 0 && i > 0)
            std::cout << std::endl;
        std::cout << std::hex << (int)data[i] << " ";
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "usage: " << argv[0] << " local ip local port remote ip remote port" << std::endl;
        return 1;
    }

    const char* localip = argv[1];
    int localport = std::stoi(argv[2]);
    const char* remoteip = argv[3];
    int remoteport = std::stoi(argv[4]);

    WSADATA wsadata;
    SOCKET recvsock, sendsock;
    sockaddr_in localaddr, remoteaddr;
    char buff[1024];
    int remoteaddrsize = sizeof(remoteaddr);

    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
        std::cerr << "wsastartup failed with error" << std::endl;
        return 1;
    }

    if ((recvsock = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        std::cerr << "socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    memset(&localaddr, 0, sizeof(localaddr));
    localaddr.sin_family = AF_INET;
    inet_pton(AF_INET, localip, &localaddr.sin_addr);
    localaddr.sin_port = htons(localport);

    if (bind(recvsock, (struct sockaddr*)&localaddr, sizeof(localaddr)) == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << std::endl;
        closesocket(recvsock);
        WSACleanup();
        return 1;
    }

    if ((sendsock = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        std::cerr << "socket creation failed with error: " << WSAGetLastError() << std::endl;
        closesocket(recvsock);
        WSACleanup();
        return 1;
    }

    memset(&remoteaddr, 0, sizeof(remoteaddr));
    remoteaddr.sin_family = AF_INET;
    inet_pton(AF_INET, remoteip, &remoteaddr.sin_addr);
    remoteaddr.sin_port = htons(remoteport);

    std::cout << "waiting for packet on " << localip << ":" << localport << "..." << std::endl;

    while (true) {
        int recv_len = recvfrom(recvsock, buff, sizeof(buff), 0, (struct sockaddr*)&remoteaddr, &remoteaddrsize);
        if (recv_len == SOCKET_ERROR) {
            std::cerr << "recvfrom failed with error: " << WSAGetLastError() << std::endl;
            break;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &remoteaddr.sin_addr, client_ip, INET_ADDRSTRLEN);

        std::cout << "received packet from " << client_ip << ":" << ntohs(remoteaddr.sin_port) << std::endl;

        unsigned char* dumpdata = new unsigned char[recv_len];
        std::memcpy(dumpdata, buff, recv_len);
        samp_decrypt(dumpdata, recv_len, ntohs(remoteaddr.sin_port), 0);

        std::cout << "decrypted data: ";
        for (size_t i = 0; i < recv_len; ++i) {
            std::cout << (char)dumpdata[i];
        }
        std::cout << std::endl;

        std::cout << "packet dump:" << std::endl;
        pkt_dump(dumpdata, recv_len);

        if (sendto(sendsock, (const char*)dumpdata, recv_len, 0, (struct sockaddr*)&remoteaddr, remoteaddrsize) == SOCKET_ERROR) {
            std::cerr << "sendto failed with error: " << WSAGetLastError() << std::endl;
        }

        delete[] dumpdata;
    }

    closesocket(recvsock);
    closesocket(sendsock);
    WSACleanup();
    return 0;
}
