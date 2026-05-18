#pragma once
#include "packet_info.h"
#include <vector>
#include <mutex>

// ─────────────────────────────────────────────────────────────────
// PacketStore: lista compartida de paquetes capturados
// El hilo de captura escribe aquí.
// El hilo de la GUI lee desde aquí.
// El mutex protege el acceso simultáneo de ambos hilos.
// ─────────────────────────────────────────────────────────────────
class PacketStore {
public:

    // Agregar un paquete (lo llama el hilo de captura)
    void agregar(const PacketInfo& pkt) {
        std::lock_guard<std::mutex> lock(mutex_);
        paquetes_.push_back(pkt);
    }

    // Obtener todos los paquetes (lo llama la GUI para dibujar)
    std::vector<PacketInfo> obtener_todos() {
        std::lock_guard<std::mutex> lock(mutex_);
        return paquetes_;
    }

    // Limpiar la lista (botón "limpiar" en la GUI)
    void limpiar() {
        std::lock_guard<std::mutex> lock(mutex_);
        paquetes_.clear();
    }

    // Cuántos paquetes hay capturados
    size_t cantidad() {
        std::lock_guard<std::mutex> lock(mutex_);
        return paquetes_.size();
    }

private:
    std::vector<PacketInfo> paquetes_;
    std::mutex              mutex_;   // protege acceso desde múltiples hilos
};