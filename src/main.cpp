#include <QApplication>
#include "gui/mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    MainWindow w;   // crea la ventana
    w.show();       // la muestra

    return app.exec();  // loop de Qt
}