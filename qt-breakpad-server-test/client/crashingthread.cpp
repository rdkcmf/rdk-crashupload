/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include "crashingthread.h"
#include <QDebug>
#include <math.h>

CrashingThread::CrashingThread(QObject *parent)
    : QThread(parent),
      th_num(-1)
{
}

void CrashingThread::run()
{
    qDebug() << "Thread " << getThreadNumber()
             << " with pid: " << thread()->currentThreadId()
             << " starting\n";

    //some work
    double result = 0.0;
    for (int i = 0;  i < 1000; ++i)
    {
        result = result + sin(i) * tan(i);
    }

    qDebug() << "Thread " << getThreadNumber() << " about to rise SIGSEGV\n";
    volatile int* x = (int*)42;
    *x = 1;
}

int CrashingThread::getThreadNumber() const
{
    return th_num;
}

void CrashingThread::setThreadNumber(int num)
{
    th_num = num;
}
