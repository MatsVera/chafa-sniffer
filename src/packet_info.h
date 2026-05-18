#pragma once
#include <string>
#include <vector>
#include <cstdint>

using namespace std;

// ─────────────────────────────────────────────────────────────────
// PacketInfo es el que representa a un paquete
// Este struct es el contrato entre todos los módulos del proyecto:
//   - capture/   lo llena con datos reales de npcap
//   - parser/    extrae los campos de los bytes crudos
//   - filters/   lo evalúa para saber si pasa el filtro
//   - export/    lo serializa a CSV o Excel
//   - gui/       lo muestra en pantalla
// ─────────────────────────────────────────────────────────────────
struct PacketInfo {

    // Metadata general
    int numero;                 // número de paquete 
    string tiempo;          // hora de captura como string hh:mm:ss:ms
    int longitud;              // longitud real del paquete en bytes

    // Capa Ethernet
    string mac_src;       // MAC origen  "AA:BB:CC:DD:EE:FF"
    string mac_dst;       // MAC destino "AA:BB:CC:DD:EE:FF"
    uint16_t    ethertype = 0; // 0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6

    // Capa IP
    string ip_src;        // IP origen  "192.168.1.1"
    string ip_dst;        // IP destino "8.8.8.8"
    uint8_t     ttl = 0;       // Time to Live
    uint8_t     protocolo_num = 0; // 6=TCP, 17=UDP, 1=ICMP

    // Protocolo como texto legible
    string protocolo;     // "TCP", "UDP", "ICMP", "ARP", "Otro"

    // Capa Transporte (TCP/UDP)
    uint16_t    puerto_src = 0;
    uint16_t    puerto_dst = 0;

    // Contenido crudo sin manejar
    vector<uint8_t> raw_bytes;
};