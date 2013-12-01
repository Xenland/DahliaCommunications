#-------------------------------------------------
#
# Project created by QtCreator 2013-11-28T02:25:04
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = dahlia_mini
TEMPLATE = app

unix:{
INCLUDEPATH += "/usr/include/botan-1.10"
LIBS += -L"/usr/lib/" -lbotan-1.10 -ldl
}

SOURCES += main.cpp\
        dahlia.cpp

HEADERS  += dahlia.h
