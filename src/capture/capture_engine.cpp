#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <pcap.h>
#include "../packet_info.h"
#include "../packet_store.h"

class CaptureEngine {
public:
    //motor de captura
    CaptureEngine(PacketStore* pkt_store): store(pkt_store),handle(nullptr),corriendo(false),contador(0),interfaces(nullptr){
        cargarInterfaces();
    }

    ~CaptureEngine(){
        if (esta_capturando()) detener();
        pcap_freealldevs(interfaces);
    }

    // Inicia la captura en la interfaz indicada y devuelve true si pudo abrir la interfaz o false si hubo error
    bool iniciar(const string& nombre_interfaz){
        int numero = 1;
        pcap_if_t* iface = interfaces;

        // punteros para poder usar
        pcap_if_t* lista[32] = {};

        while (iface != nullptr && numero <= 32) {
            lista[numero] = iface;
            if(string(iface->name) == nombre_interfaz) break;
            iface = iface->next;
            numero++;
        }

        if (numero == 32){
            pcap_freealldevs(interfaces);
            return false;
        }

        // parametros nombre, bytes a capturar por paquete, modo promiscuo, timeout en ms, buffer de error
        handle = pcap_open_live(nombre_interfaz.c_str(), 65535, 1, 1000, errbuf); //pporue ncap esta en c

        if (handle == nullptr) {
            cerr << "Error abriendo interfaz: " << errbuf << "" << endl;
            pcap_freealldevs(interfaces);
            return false;
        }

        corriendo = true;

        //crear el hilo
        hilo = thread(&CaptureEngine::loop_captura, this);

        return true;

    }

    // Detiene la captura
    // primero parar el loop, luego esperas al hilo, luego cierras
    void detener(){
        pcap_breakloop(handle);
        hilo.join();
        pcap_close(handle);
        corriendo = false;
    }

    bool esta_capturando() const{
        return corriendo;
    }

    int cargarInterfaces(){
        // interfaces
        if (pcap_findalldevs(&interfaces, errbuf) == -1) {
            cerr << "Error al buscar las interfaces" << errbuf << "" << endl;
            return 1;
        }
        return 0;
    }

private:

    // funcion handler de hilo
    void loop_captura(){
        pcap_loop(handle, -1, packetHandler, this);
    }

    static void packetHandler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
        CaptureEngine* engine = reinterpret_cast<CaptureEngine*>(user_data);
       

        PacketInfo info_pkt;
        info_pkt.longitud = header->len;
        long seg = header->ts.tv_sec;
        long ms = header->ts.tv_usec;

        info_pkt.tiempo = to_string(seg) + "." + std::to_string(ms);
        info_pkt.raw_bytes = vector<uint8_t>(packet, packet + header->caplen);
        info_pkt.numero = ++(engine->contador); // lleva la cuenta de paquetes capturados
        engine->store->agregar(info_pkt); 
    }

    // Atributos
    PacketStore* store;              // donde guardamos los paquetes, lista
    pcap_t* handle;                 // el handle de npcap
    thread hilo;                    // el hilo de captura
    atomic<bool> corriendo;         // controla si el loop sigue activo
    int contador;                   // num de paquete actual
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;

};