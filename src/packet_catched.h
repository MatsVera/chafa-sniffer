#pragma once
#include "packet_info.h"
#include <vector>
#include <mutex>

// lista de paquetes capturados
// captura lo edita y GUI lo le

class PacketCatched {
public:

    // Agregar un paquete 
    void agregar(const PacketInfo& pkt) {
        lock_guard<mutex> lock(mtx); //bloquear el mutex y se desbloquea cuando se destruye
        paquetes.push_back(pkt);
    }

    // Obtener todos los paquetes
    //la gui lo llama para poder imprimir**
    vector<PacketInfo> obtener_todos() {
        lock_guard<mutex> lock(mtx);
        return paquetes;
    }

    // Limpiar la lista, limpiar en gui
    void limpiar() {
        lock_guard<mutex> lock(mtx);
        paquetes.clear();
    }

    // Cuántos paquetes hay capturados
    size_t cantidad() {
        lock_guard<mutex> lock(mtx);
        return paquetes.size();
    }

private:
    vector<PacketInfo> paquetes;
    mutex mtx;   // protege acceso desde varios hilos
};