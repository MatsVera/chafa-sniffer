#include <iostream>
#include <pcap.h>
#include "capture/capture.h"
#include "parser/parser.h"
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

    auto paquetes = pktCatched.obtener_todos();

cout << "Primeros paquetes capturados" << endl;

int contador = 0;

for (auto p : paquetes) {
    if (contador++ == 5)
        break;

    cout << "Info paquete " << p.numero << endl 
    << "  Tiempo    : " << p.tiempo << endl
    << "  Longitud  : " << p.longitud << endl
    << "  MAC origen   : " << p.mac_org << endl
    << "  MAC destino   : " << p.mac_dst << endl
    << "  IP origen    : " << p.ip_org << endl
    << "  IP destino  : " << p.ip_dst << endl
    << "  Protocolo : " << p.protocolo << endl
    << "  Puerto origen: " << p.puerto_org << endl
    << "  Puerto destino: " << p.puerto_dst << endl;
}

    return 0;
}