#-------------------------------------------------
#
# Project created by QtCreator 2015-06-09T12:14:47
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = kalina
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    common.cpp \
    kalina_128_128.cpp \
    kalina_256_256.cpp \
    kalina_512_512.cpp

HEADERS += \
    common.h \
    galua_table.h \
    kalina_128.h \
    kalina_tables.h \
    kalina_256_256.h \
    kalina_512_512.h
