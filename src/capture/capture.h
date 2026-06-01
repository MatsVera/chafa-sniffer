#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <pcap.h>
#include <iostream>
#include "../packet_info.h"
#include "../packet_catched.h"
#include "../parser/parser.h"
using namespace std;

class Capture {
public:

    //motor de captura
    Capture(PacketCatched* pkt_ctch): ctch(pkt_ctch),handle(nullptr),corriendo(false),pausado(false),contador(0),interfaces(nullptr){
        cargarInterfaces();
    }

    ~Capture(){
        if (esta_capturando()) detener();
        pcap_freealldevs(interfaces);
    }

    // Inicia la captura en la interfaz indicada y devuelve true si pudo abrir la interfaz o false si hubo error
    bool iniciar(const string& nombre_interfaz){
        int numero = 1;
        pcap_if_t* iface = interfaces;
        interfaz_actual = nombre_interfaz;
        // punteros para poder usar
        pcap_if_t* lista[32] = {};

        while (iface != nullptr && numero <= 32)
        {
            if(string(iface->name) == nombre_interfaz)
                break;

            iface = iface->next;
            numero++;
        }

        if (iface == nullptr)
        {
            return false;
        }

        // parametros nombre, bytes a capturar por paquete, modo promiscuo, timeout en ms, buffer de error
        handle = pcap_open_live(nombre_interfaz.c_str(), 65535, 1, 1000, errbuf); //pporue ncap esta en c

        if (handle == nullptr) {
            //cout << "Error abriendo interfaz: " << errbuf << "" << endl;
            return false;
        }

        corriendo = true;

        //crear el hilo
        hilo = thread(&Capture::loop_captura, this);

        return true;

    }
    PacketCatched* obtenerPaquetes()
    {
        return ctch;
    }

    // Detiene la captura
    // primero parar el loop, luego espera al hilo, luego ya se puede cerrar
    void detener(){
        pcap_breakloop(handle);
        hilo.join();
        pcap_close(handle);
        corriendo = false;
    }
    void pausar(){
        pausado=true;
    }
    void reanudar(){
        pausado=false;
    }
    void reiniciar()
    {
        if(corriendo)
        {
            pcap_breakloop(handle);

            if(hilo.joinable())
                hilo.join();

            pcap_close(handle);
            corriendo = false;
        }

        contador = 0;
        pausado =false;
        ctch->limpiar();
        iniciar(interfaz_actual);
    }

    bool esta_capturando() {
        return corriendo;
    }

    int cargarInterfaces(){
        // interfaces
        if (pcap_findalldevs(&interfaces, errbuf) == -1) {
            //cout << "Error al buscar las interfaces" << errbuf << "" << endl;
            return 1;
        }
        return 0;
    }

    void mostrarTodas(){
        if (interfaces == nullptr) return;

        cout << "Interfaces de red disponibles:" << endl;
        cout << "--------------------------------" << endl;

        int numero = 1;
        pcap_if_t* iface = interfaces;

        while (iface != nullptr && numero <= 32) {
            cout << numero << ". " << iface->name << "" << endl;
            if (iface->description)
                cout << "   " << iface->description << "" << endl;
            iface = iface->next;
            numero++;
        }
    }

    string obtenerNombre(const string& descripcion)
    {
        pcap_if_t* iface = interfaces;

        while(iface != nullptr)
        {
            if(iface->description &&
                string(iface->description) == descripcion)
            {
                return string(iface->name);
            }

            iface = iface->next;
        }

        return descripcion;
    }
    vector<string> obtenerInterfaces(){
        vector<string> lista;
        pcap_if_t * iface = interfaces;
        while(iface!= nullptr){
            if(iface->description){
                lista.push_back(iface->description);
            }
            else{
                lista.push_back(iface->name);
            }
            iface = iface->next;
        }
        return lista;
    }

private:
    //atributos
    Parser parser;
    PacketCatched* ctch;              // donde guardamos los paquetes, lista
    pcap_t* handle;                 // el handle de npcap
    thread hilo;                    // el hilo de captura
    atomic<bool> corriendo;         // controla si el loop sigue activo
    atomic<bool> pausado;
    int contador;                   // num de paquete actual
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;
    string interfaz_actual;


    //static void parsear(const u_char* crudo, int longitud, PacketInfo& info
    void parsear(const u_char* crudo, int longitud, PacketInfo& info){
        parser.parsear(crudo, longitud, info);
    }

    // funcion handler de hilo
    void loop_captura(){
        pcap_loop(handle, -1, packetHandler, reinterpret_cast<u_char*>(this));
    }

    static void packetHandler(u_char* data, const struct pcap_pkthdr* header, const u_char* packet) {
        Capture* cap = reinterpret_cast<Capture*>(data);
        if(cap->pausado)
            return;
        PacketInfo info_pkt;
        info_pkt.longitud = header->len;
        long seg = header->ts.tv_sec;
        long ms = header->ts.tv_usec;

        info_pkt.tiempo = to_string(seg) + "." + to_string(ms);
        info_pkt.bytes = vector<uint8_t>(packet, packet + header->caplen);
        info_pkt.numero = ++(cap->contador); // lleva la cuenta de paquetes capturados

        //.data()
        cap->parsear(info_pkt.bytes.data(), info_pkt.longitud, info_pkt);

        cap->ctch->agregar(info_pkt); 
    }
};