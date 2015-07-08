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

TEMPLATE = app


SOURCES += main.cpp

OTHER_FILES += \
    ldap.schema/two-factor_openldap.schema \
    .gitignore \
    ldap.schema/README.md \
    README.md \
    ldap.schema/Makefile
