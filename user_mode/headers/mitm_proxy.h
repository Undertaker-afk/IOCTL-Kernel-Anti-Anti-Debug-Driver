#pragma once

#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <functional>

#pragma comment(lib, "wininet.lib")

struct NetworkPacket
{
    std::vector<BYTE> data;
    std::string source_ip;
    std::string dest_ip;
    USHORT source_port;
    USHORT dest_port;
    DWORD timestamp;
    bool is_incoming;
};

class MitmProxy
{
private:
    SOCKET proxy_socket;
    SOCKET target_socket;
    USHORT proxy_port;
    USHORT target_port;
    std::string target_host;
    bool is_running;
    std::thread proxy_thread;
    std::mutex packet_mutex;
    std::vector<NetworkPacket> captured_packets;
    std::function<void(const NetworkPacket&)> packet_callback;

public:
    MitmProxy();
    ~MitmProxy();

    bool StartProxy(USHORT listen_port, const std::string& target_host, USHORT target_port);
    void StopProxy();
    bool IsRunning() const { return is_running; }
    
    void SetPacketCallback(std::function<void(const NetworkPacket&)> callback);
    std::vector<NetworkPacket> GetCapturedPackets();
    void ClearCapturedPackets();
    
    // Packet modification functions
    bool ModifyPacket(NetworkPacket& packet, const std::vector<BYTE>& new_data);
    bool BlockPacket(const NetworkPacket& packet);

private:
    void ProxyWorker();
    void HandleClientConnection(SOCKET client_socket);
    NetworkPacket CreatePacketFromData(const std::vector<BYTE>& data, bool is_incoming);
};
