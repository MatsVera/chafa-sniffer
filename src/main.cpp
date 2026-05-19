#include <iostream>
#include <pcap.h>
#include "capture/capture_engine.h"
#include <conio.h>

using namespace std;

int main(){
    PacketStore pktStore;

    CaptureEngine cap(&pktStore);

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
        tecla = _getch();

        if (tecla == 's' || tecla == 'S'){
            cout << "Deteniendo captura" << endl;
            break;
        }
    }
    
    cap.detener();

    return 0;
}