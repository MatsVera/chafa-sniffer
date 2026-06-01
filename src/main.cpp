#include <iostream>
#include <pcap.h>
#include "capture/capture.h"
#include "parser/parser.h"
#include "filters/filters.h" // <-- Incluimos tu motor de filtros
#include <conio.h>

using namespace std;

int main(){
    PacketCatched pktCatched;
    Parser parser;
    Capture cap(&pktCatched);

    cap.mostrarTodas();
    int i;
    string nom;

    cout << "Ingresa la interfaz que deseas verificar: (numero) " ;
    cin >> i;

    nom = cap.obtenerNombre(i);

    if (nom.empty()) {
        cout << "opcion invalida" << endl;
        return 1;
    }

    cap.iniciar(nom);

    char tecla;
    while (true) {
        if(_kbhit()){
            tecla = _getch();
            if (tecla == 's' || tecla == 'S'){
                cout << "Deteniendo captura" << endl;
                break;
            }
        }
    }
    
    cap.detener();

    // Recorremos todos los paquetes guardados originalmente
    auto paquetes = pktCatched.obtener_todos();

    // =========================================================================
    // SOLICITUD DE FILTROS EN CONSOLA
    // =========================================================================
    cout << "\n========================================" << endl;
    cout << "   CONFIGURACIÓN DE FILTROS (TERMINAL)   " << endl;
    cout << "========================================" << endl;
    
    FilterCriteria misFiltros;
    
    cout << "Filtrar por IP Origen (ENTER para omitir): ";
    cin.ignore(); // Limpia el buffer de entrada
    getline(cin, misFiltros.ip_org);

    cout << "Filtrar por Protocolo (TCP/UDP/ICMP o ENTER para omitir): ";
    getline(cin, misFiltros.protocolo);

    cout << "Filtrar por Puerto Destino (0 para omitir): ";
    int puerto_aux;
    cin >> puerto_aux;
    misFiltros.puerto_dst = static_cast<uint16_t>(puerto_aux);

    cout << "\n========================================" << endl;
    cout << "        RESULTADOS FILTRADOS            " << endl;
    cout << "========================================" << endl;

    int contador_mostrados = 0;

    for (auto p : paquetes) {
        // Usamos tu FilterEngine para evaluar el paquete individualmente
        if (FilterEngine::cumpleFiltros(p, misFiltros)) {
            
            if (contador_mostrados++ == 5) // Límite de 5 impresiones en pantalla
                break;

            cout << "Info paquete " << p.numero << " [" << p.protocolo << "]" << endl 
                 << "  Tiempo        : " << p.tiempo << endl
                 << "  Longitud      : " << p.longitud << endl
                 << "  MAC origen    : " << p.mac_org << endl
                 << "  MAC destino   : " << p.mac_dst << endl
                 << "  IP origen     : " << p.ip_org << endl
                 << "  IP destino    : " << p.ip_dst << endl
                 << "  Puerto origen : " << p.puerto_org << endl
                 << "  Puerto destino: " << p.puerto_dst << endl;
            cout << "----------------------------------------" << endl;
        }
    }

    if (contador_mostrados == 0) {
        cout << "Ningun paquete coincidio con los filtros especificados." << endl;
    } else {
        cout << "Se listaron los primeros paquetes que cumplen el criterio." << endl;
    }

    return 0;
}