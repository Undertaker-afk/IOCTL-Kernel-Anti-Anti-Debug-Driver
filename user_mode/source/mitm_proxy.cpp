#include "../headers/mitm_proxy.h"
#include <ws2tcpip.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

MitmProxy::MitmProxy()
    : proxy_socket(INVALID_SOCKET), target_socket(INVALID_SOCKET),
      proxy_port(0), target_port(0), is_running(false)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

MitmProxy::~MitmProxy()
{
    StopProxy();
    WSACleanup();
}

bool MitmProxy::StartProxy(USHORT listen_port, const std::string& target_host, USHORT target_port)
{
    if (is_running)
    {
        return false;
    }

    this->proxy_port = listen_port;
    this->target_host = target_host;
    this->target_port = target_port;

    // Create listening socket
    proxy_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (proxy_socket == INVALID_SOCKET)
    {
        return false;
    }

    // Bind to listening port
    sockaddr_in listen_addr = {};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(proxy_socket, (sockaddr*)&listen_addr, sizeof(listen_addr)) == SOCKET_ERROR)
    {
        closesocket(proxy_socket);
        proxy_socket = INVALID_SOCKET;
        return false;
    }

    // Start listening
    if (listen(proxy_socket, SOMAXCONN) == SOCKET_ERROR)
    {
        closesocket(proxy_socket);
        proxy_socket = INVALID_SOCKET;
        return false;
    }

    is_running = true;
    proxy_thread = std::thread(&MitmProxy::ProxyWorker, this);

    return true;
}

void MitmProxy::StopProxy()
{
    is_running = false;

    if (proxy_socket != INVALID_SOCKET)
    {
        closesocket(proxy_socket);
        proxy_socket = INVALID_SOCKET;
    }

    if (target_socket != INVALID_SOCKET)
    {
        closesocket(target_socket);
        target_socket = INVALID_SOCKET;
    }

    if (proxy_thread.joinable())
    {
        proxy_thread.join();
    }
}

void MitmProxy::SetPacketCallback(std::function<void(const NetworkPacket&)> callback)
{
    packet_callback = callback;
}

std::vector<NetworkPacket> MitmProxy::GetCapturedPackets()
{
    std::lock_guard<std::mutex> lock(packet_mutex);
    return captured_packets;
}

void MitmProxy::ClearCapturedPackets()
{
    std::lock_guard<std::mutex> lock(packet_mutex);
    captured_packets.clear();
}

bool MitmProxy::ModifyPacket(NetworkPacket& packet, const std::vector<BYTE>& new_data)
{
    packet.data = new_data;
    return true;
}

bool MitmProxy::BlockPacket(const NetworkPacket& packet)
{
    // Mark packet as blocked (implementation specific)
    return true;
}

void MitmProxy::ProxyWorker()
{
    while (is_running)
    {
        SOCKET client_socket = accept(proxy_socket, nullptr, nullptr);
        if (client_socket != INVALID_SOCKET)
        {
            std::thread client_thread(&MitmProxy::HandleClientConnection, this, client_socket);
            client_thread.detach();
        }
    }
}

void MitmProxy::HandleClientConnection(SOCKET client_socket)
{
    // Connect to target server
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET)
    {
        closesocket(client_socket);
        return;
    }

    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_host.c_str(), &server_addr.sin_addr);

    if (connect(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        closesocket(client_socket);
        closesocket(server_socket);
        return;
    }

    // Relay data between client and server
    fd_set read_fds;
    while (is_running)
    {
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(server_socket, &read_fds);

        timeval timeout = { 1, 0 }; // 1 second timeout
        int result = select(0, &read_fds, nullptr, nullptr, &timeout);

        if (result <= 0)
        {
            continue;
        }

        char buffer[4096];
        int bytes_received;

        // Client to server
        if (FD_ISSET(client_socket, &read_fds))
        {
            bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0)
            {
                break;
            }

            std::vector<BYTE> data(buffer, buffer + bytes_received);
            NetworkPacket packet = CreatePacketFromData(data, false);

            {
                std::lock_guard<std::mutex> lock(packet_mutex);
                captured_packets.push_back(packet);
            }

            if (packet_callback)
            {
                packet_callback(packet);
            }

            send(server_socket, buffer, bytes_received, 0);
        }

        // Server to client
        if (FD_ISSET(server_socket, &read_fds))
        {
            bytes_received = recv(server_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0)
            {
                break;
            }

            std::vector<BYTE> data(buffer, buffer + bytes_received);
            NetworkPacket packet = CreatePacketFromData(data, true);

            {
                std::lock_guard<std::mutex> lock(packet_mutex);
                captured_packets.push_back(packet);
            }

            if (packet_callback)
            {
                packet_callback(packet);
            }

            send(client_socket, buffer, bytes_received, 0);
        }
    }

    closesocket(client_socket);
    closesocket(server_socket);
}

NetworkPacket MitmProxy::CreatePacketFromData(const std::vector<BYTE>& data, bool is_incoming)
{
    NetworkPacket packet;
    packet.data = data;
    packet.is_incoming = is_incoming;
    packet.timestamp = GetTickCount();
    packet.source_port = is_incoming ? target_port : 0;
    packet.dest_port = is_incoming ? proxy_port : target_port;
    packet.source_ip = is_incoming ? target_host : "127.0.0.1";
    packet.dest_ip = is_incoming ? "127.0.0.1" : target_host;

    return packet;
}
