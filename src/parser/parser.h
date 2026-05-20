#pragma once
#include "../packet_info.h"
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <pcap.h>
#include <cstdint>
#include <winsock2.h>

#pragma pack(push, 1)
/*
ip_header — 20 bytes mínimo:

version_ihl: 1 byte — versión + longitud de cabecera
tos: 1 byte — tipo de servicio
total_length: 2 bytes
id: 2 bytes
flags_offset: 2 bytes cuando se dividen paquetes
ttl: 1 byte
protocol: 1 byte — 6=TCP, 17=UDP, 1=ICMP
checksum: 2 bytes
src_ip: 4 bytes
dst_ip: 4 bytes
*/

struct ip_header{
    uint8_t version_ihl;
    uint8_t tipo_servicio;
    uint16_t longitud_total;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t chk_sum;
    uint32_t ip_org;
    uint32_t ip_dst;
};

//dst_mac: 6 bytes — MAC destino
// src_mac: 6 bytes — MAC origen
// ethertype: 2 bytes — tipo de protocolo
struct ethernet_header{
    uint8_t mac_dst[6];   //mascara de los ultimos 2 bytes
    uint8_t mac_org[6];   //mascara de los ultimos 2 bytes
    uint16_t protocol;           //sin mascara
};

/*

src_port: 2 bytes
dst_port: 2 bytes
seq: 4 bytes
ack: 4 bytes
data_offset: 1 byte
flags: 1 byte
window: 2 bytes
checksum: 2 bytes
urgent: 2 bytes*/
struct tcp_header{
    uint16_t puerto_org;
    uint16_t puerto_dst;
    uint32_t seq; //numero de secuencia
    uint32_t ack;
    uint8_t data_offset; 
    uint8_t flags;  
    uint16_t window;
    uint16_t chk_sum;
    uint16_t urgent;

};

#pragma pack(pop)

using namespace std;

class Parser {
    public:
    //todas las funciones se hacen static para poder usarlas sin llamar un objeto de la clase
        static void parsear(const u_char* crudo, int longitud, PacketInfo& info){
        
            // convertir ethernet
            if (longitud < 14) return; // paquete muy corto

            const ethernet_header* eth = reinterpret_cast<const ethernet_header*>(crudo);

            info.mac_org = mac_string(eth->mac_org);
            info.mac_dst = mac_string(eth->mac_dst);

            uint16_t ethertype = ntohs(eth->protocol);
            info.ethertype = ethertype;

            // procesando ipv4
            if (ethertype != 0x0800) {
                info.protocolo = "No-IPv4";
                return;
            }

            // conversion de ip 
            if (longitud < 14 + 20) return;

            const ip_header* ip = reinterpret_cast<const ip_header*>(crudo + 14);

            info.ip_org  = ip_string(ip->ip_org);
            info.ip_dst  = ip_string(ip->ip_dst);
            info.ttl     = ip->ttl;
            info.protocolo_num = ip->protocol;

            // Calcular en donde empieza tcp/udp
            // ihl son los 4 bits bajos de version_ihl, multiplicados por 4
            int ip_header_len = (ip->version_ihl & 0x0F) * 4;

            // tcp, udp e imcp
            if (ip->protocol == 6) { // TCP
                info.protocolo = "TCP";
                if (longitud < 14 + ip_header_len + 20) return;

                const tcp_header* tcp = reinterpret_cast<const tcp_header*>(crudo + 14 + ip_header_len);
                info.puerto_org = ntohs(tcp->puerto_org);
                info.puerto_dst = ntohs(tcp->puerto_dst);

            } else if (ip->protocol == 17) { // UDP
                info.protocolo = "UDP";
                if (longitud < 14 + ip_header_len + 8) return;

                // udp_header 
                //puerto origen y destino 2
                //longitud y cksum 2
                const uint8_t* udp = crudo + 14 + ip_header_len;
                info.puerto_org = ntohs(*reinterpret_cast<const uint16_t*>(udp)); // primeros 2 bytes
                info.puerto_dst = ntohs(*reinterpret_cast<const uint16_t*>(udp + 2)); // siguientes 2 bytes

            } else if (ip->protocol == 1) { // ICMP
                info.protocolo = "ICMP";
                // icmp no tiene puertos y se deja en 0
            } else {
                info.protocolo = "Otro";
            }
        }

        void mostrar(){

        }
    private:

        //para poder convertirla usar snptrinf y manejar bien valores hex
        static string mac_string(const uint8_t* mac){
            char buff[18];
            snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            return string(buff);
        }
        static string ip_string(uint32_t ip){
            uint32_t ip_host = ntohl(ip); //pasar a little endian porque se recibe en big endian de la red

            //descomprimir octetos
            return to_string((ip_host >> 24) & 0xFF) + "." + to_string((ip_host >> 16) & 0xFF) + "." + to_string((ip_host >> 8)  & 0xFF) + "." + to_string( ip_host        & 0xFF);
        }
};