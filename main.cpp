#include "dahlia.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    dahlia w;
    w.setWindowTitle(QString("Dahlia [Mini Prototype]"));
    w.show();

    return a.exec();
}
