TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        arphdr.cpp \
        ethhdr.cpp \
        ip.cpp \
        mac.cpp \
        main.c

HEADERS += \
    arphdr.h \
    ethhdr.h \
    ip.h \
    mac.h
