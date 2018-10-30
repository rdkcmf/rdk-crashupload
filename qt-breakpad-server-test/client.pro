##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
QT       += core
QT       -= gui

CONFIG   += debug
CONFIG   += console
CONFIG   -= app_bundle

linux-mipsel-uclibc-g++ {
    TARGET = client-bcom
    BREAKPAD_DIR = google-breakpad-broadcom
} else: linux-x86-g++-canmore {
    TARGET = client-xg1
    BREAKPAD_DIR = google-breakpad-xg1
} else {
    TARGET = client-pc
    BREAKPAD_DIR = google-breakpad-pc
}

TEMPLATE = app

INCLUDEPATH += $$PWD/../../$$BREAKPAD_DIR/src
LIBS += $$PWD/../../$$BREAKPAD_DIR/src/client/linux/libbreakpad_client.a

DEFINES += USE_GOOGLE_BREAKPAD

SOURCES += $$PWD/client/main.cpp \
           $$PWD/client/crashingthread.cpp

HEADERS += \
           $$PWD/client/crashingthread.h

isEmpty(PREFIX) : PREFIX = $$PWD
target.path = $$PREFIX/built
INSTALLS += target

