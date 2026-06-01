#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "capturawindow.h"
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->btnIniciar->setEnabled(false);

    captura = new Capture(&paquetes);

    cargarInterfaces();
    connect(ui->interfaces,
            &QListWidget::itemClicked,
            this,
            [this]()
            {
                ui->btnIniciar->setEnabled(true);
            });
    connect(ui->btnIniciar,
            &QPushButton::clicked,
            this,
            &MainWindow::iniciarCaptura);

}

MainWindow::~MainWindow()
{
    delete captura;
    delete ui;
}

void MainWindow::cargarInterfaces()
{
    ui->interfaces->clear();

    auto lista = captura->obtenerInterfaces();

    for(const auto& nombre : lista)
    {
        ui->interfaces->addItem(
            QString::fromStdString(nombre)
            );
    }
    connect(ui->interfaces,
            &QListWidget::itemDoubleClicked,
            this,
            &MainWindow::iniciarCaptura);
}


void MainWindow::iniciarCaptura()
{
    capturawindow* ventanaCaptura;
    QListWidgetItem* item =
        ui->interfaces->currentItem();

    if(!item)
        return;

    std::string nombreReal =
        captura->obtenerNombre(
            item->text().toStdString()
            );

    if(captura->iniciar(nombreReal))
    {
        ventanaCaptura =
            new capturawindow(captura);

        ventanaCaptura->show();

        this->hide();
    }
}

