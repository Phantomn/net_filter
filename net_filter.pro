TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.cpp
LIBS += -lnetfilter_queue

HEADERS += \
    struct.h
