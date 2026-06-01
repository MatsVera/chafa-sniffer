#include "capturawindow.h"
#include "ui_capturawindow.h"

capturawindow::capturawindow(Capture* cap,
                             QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::capturawindow)
    , captura(cap)
    , ultimoPaqueteMostrado(0)
{
    ui->setupUi(this);
    connect(ui->btn_Detener,
            &QPushButton::clicked,
            this,
            &capturawindow::on_btn_Detener_clicked);

    connect(ui->btn_Reanudar,
            &QPushButton::clicked,
            this,
            &capturawindow::on_btn_Reanudar_clicked);

    connect(ui->btn_Reiniciar,
            &QPushButton::clicked,
            this,
            &capturawindow::on_btn_Reiniciar_clicked);
    // Configurar tabla
    ui->tablePaquetes->setColumnCount(6);

    QStringList headers;
    headers << "No."
            << "Tiempo"
            << "Origen"
            << "Destino"
            << "Protocolo"
            << "Longitud";

    ui->tablePaquetes->setHorizontalHeaderLabels(headers);

    ui->tablePaquetes->horizontalHeader()
        ->setStretchLastSection(true);

    ui->tablePaquetes->setEditTriggers(
        QAbstractItemView::NoEditTriggers
        );

    ui->tablePaquetes->setSelectionBehavior(
        QAbstractItemView::SelectRows
        );

    // Timer
    timer = new QTimer(this);

    connect(timer,
            &QTimer::timeout,
            this,
            &capturawindow::actualizarTabla);
    connect(ui->tablePaquetes,
            &QTableWidget::itemClicked,
            this,
            &capturawindow::mostrarDetalles);

    timer->start(50);
}

capturawindow::~capturawindow()
{
    delete ui;
}

void capturawindow::actualizarTabla()
{
    auto paquetes =
        captura->obtenerPaquetes()->obtener_todos();

    for(size_t i = ultimoPaqueteMostrado;
         i < paquetes.size();
         i++)
    {
        int fila = ui->tablePaquetes->rowCount();

        ui->tablePaquetes->insertRow(fila);

        ui->tablePaquetes->setItem(fila,0,
                                   new QTableWidgetItem(
                                       QString::number(paquetes[i].numero)));

        ui->tablePaquetes->setItem(fila,1,
                                   new QTableWidgetItem(
                                       QString::fromStdString(paquetes[i].tiempo)));

        ui->tablePaquetes->setItem(fila,2,
                                   new QTableWidgetItem(
                                       QString::fromStdString(paquetes[i].ip_org)));

        ui->tablePaquetes->setItem(fila,3,
                                   new QTableWidgetItem(
                                       QString::fromStdString(paquetes[i].ip_dst)));

        ui->tablePaquetes->setItem(fila,4,
                                   new QTableWidgetItem(
                                       QString::fromStdString(paquetes[i].protocolo)));

        ui->tablePaquetes->setItem(fila,5,
                                   new QTableWidgetItem(
                                       QString::number(paquetes[i].longitud)));
    }

    ultimoPaqueteMostrado = paquetes.size();

    ui->tablePaquetes->scrollToBottom();
    if(ui->tablePaquetes->currentRow() == -1 &&
        ui->tablePaquetes->rowCount() > 0)
    {
        ui->tablePaquetes->selectRow(0);
    }

}
void capturawindow::mostrarDetalles()
{
    int fila = ui->tablePaquetes->currentRow();

    if(fila < 0)
        return;

    auto paquetes =
        captura->obtenerPaquetes()->obtener_todos();

    if(fila >= paquetes.size())
        return;

    const PacketInfo& pkt = paquetes[fila];

    ui->treeDetalles->clear();

    // Frame
    QTreeWidgetItem* frame =
        new QTreeWidgetItem(ui->treeDetalles);

    frame->setText(0,
                   QString("Frame %1: %2 bytes")
                       .arg(pkt.numero)
                       .arg(pkt.longitud));

    // Ethernet
    QTreeWidgetItem* eth =
        new QTreeWidgetItem(ui->treeDetalles);

    eth->setText(0,
                 QString("Ethernet II"));

    new QTreeWidgetItem(eth,
                        QStringList()
                            << ("Source: " +
                                QString::fromStdString(pkt.mac_org)));

    new QTreeWidgetItem(eth,
                        QStringList()
                            << ("Destination: " +
                                QString::fromStdString(pkt.mac_dst)));

    // IP
    QTreeWidgetItem* ip =
        new QTreeWidgetItem(ui->treeDetalles);

    ip->setText(0,
                "Internet Protocol");

    new QTreeWidgetItem(ip,
                        QStringList()
                            << ("Source: " +
                                QString::fromStdString(pkt.ip_org)));

    new QTreeWidgetItem(ip,
                        QStringList()
                            << ("Destination: " +
                                QString::fromStdString(pkt.ip_dst)));

    new QTreeWidgetItem(ip,
                        QStringList()
                            << ("TTL: " +
                                QString::number(pkt.ttl)));

    // Protocolo
    QTreeWidgetItem* proto =
        new QTreeWidgetItem(ui->treeDetalles);

    proto->setText(0,
                   QString::fromStdString(pkt.protocolo));

    new QTreeWidgetItem(proto,
                        QStringList()
                            << ("Puerto origen: " +
                                QString::number(pkt.puerto_org)));

    new QTreeWidgetItem(proto,
                        QStringList()
                            << ("Puerto destino: " +
                                QString::number(pkt.puerto_dst)));

    //ui->treeDetalles->expandAll();
    mostrarHex(pkt);
}
void capturawindow::mostrarHex(const PacketInfo& pkt)
{
    QString salida;

    for(size_t i = 0; i < pkt.bytes.size(); i += 16)
    {
        // OFFSET
        salida += QString("%1   ")
                      .arg(i, 4, 16, QChar('0'))
                      .toUpper();

        QString hexParte;
        QString asciiParte;

        for(size_t j = 0; j < 16; j++)
        {
            if(i + j < pkt.bytes.size())
            {
                uint8_t byte = pkt.bytes[i + j];

                // HEX
                hexParte += QString("%1 ")
                                .arg(byte, 2, 16, QChar('0'))
                                .toUpper();

                // ASCII
                if(byte >= 32 && byte <= 126)
                    asciiParte += QChar(byte);
                else
                    asciiParte += ".";
            }
            else
            {
                hexParte += "   ";
                asciiParte += " ";
            }
        }

        salida += hexParte + "   " + asciiParte + "\n";
    }

    ui->txtHex->setPlainText(salida);
}
void capturawindow::on_btn_Detener_clicked()
{
    if(captura)
        captura->pausar();

    timer->stop();
}
void capturawindow::on_btn_Reanudar_clicked()
{
    if(captura)
        captura->reanudar();

    timer->start(50);
}
void capturawindow::on_btn_Reiniciar_clicked()
{
    if(captura)
    {
        ui->tablePaquetes->setRowCount(0);
        ultimoPaqueteMostrado = 0;
        ui->tablePaquetes->clearContents();
        captura->reiniciar();
    }
}