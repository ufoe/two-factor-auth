#-------------------------------------------------
#
# Project created by QtCreator 2015-07-08T08:09:04
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = two-factor-auth
CONFIG   += console
CONFIG   -= app_bundle
LIBS += -lldap -llber -lcrypto

TEMPLATE = app


SOURCES += \
    manager.cpp \
    libs/tfldap.cpp \
    libs/totp.cpp

OTHER_FILES += \
    ldap.schema/two-factor_openldap.schema \
    .gitignore \
    ldap.schema/README.md \
    README.md \
    ldap.schema/Makefile

HEADERS += \
    config.h \
    libs/tfldap.h \
    libs/totp.h
