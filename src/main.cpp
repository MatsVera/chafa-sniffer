#include <iostream>
#include <pcap.h>

using namespace std;

// npcap llama esta funcion por cada paquete capturado
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    
    cout << "Paquete capturado" << endl;
    cout << "  Longitud: " << header->len    << " bytes" << endl;
    cout << "  Longitud capturada: " << header->caplen << " bytes" << endl;
    cout << "  Timestamp       : " << header->ts.tv_sec << "s "
                                        << header->ts.tv_usec << "us" << endl;
    cout << "---------------------------------" << endl;
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;

    // interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        cerr << "Error al buscar las interfaces" << errbuf << "" << endl;
        return 1;
    }

    cout << "Interfaces de red disponibles:" << endl;
    cout << "--------------------------------" << endl;

    int numero = 1;
    pcap_if_t* iface = interfaces;

    // punteros para poder usar
    pcap_if_t* lista[32] = {};

    while (iface != nullptr && numero <= 32) {
        lista[numero] = iface;
        cout << numero << ". " << iface->name << "" << endl;
        if (iface->description)
            cout << "   " << iface->description << "" << endl;
        iface = iface->next;
        numero++;
    }

    // elegir interfaz
    int eleccion = 0;
    cout << "Elige una interfaz: ";
    cin  >> eleccion;

    if (eleccion < 1 || eleccion >= numero || lista[eleccion] == nullptr) {
        cerr << "Eleccion invalida." << endl;
        pcap_freealldevs(interfaces);
        return 1;   
    }

    const char* nombre_interfaz = lista[eleccion]->name;
    cout << "Abriendo: " << nombre_interfaz << "" << endl;

    // parametros nombre, bytes a capturar por paquete, modo promiscuo, timeout en ms, buffer de error
    pcap_t* handle = pcap_open_live(nombre_interfaz, 65535, 1, 1000, errbuf);

    if (handle == nullptr) {
        cerr << "Error abriendo interfaz: " << errbuf << "" << endl;
        pcap_freealldevs(interfaces);
        return 1;
    }

    cout << "Capturando paquetes" << endl << endl;

    //parameetros handle, cantidad de paquetes (-1 = infinito), funcion callback, datos extra para el callback
    pcap_loop(handle, -1, packet_handler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(interfaces);

    return 0;
}