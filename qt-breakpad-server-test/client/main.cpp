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
#include <QCoreApplication>
#include <QDebug>
#include "crashingthread.h"
#include <sys/poll.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#if defined(USE_GOOGLE_BREAKPAD)
#include "client/linux/handler/exception_handler.h"
#include "client/linux/crash_generation/crash_generation_server.h"
#include "common/linux/eintr_wrapper.h"
#include "common/linux/linux_libc_support.h"
#include "third_party/lss/linux_syscall_support.h"

using namespace google_breakpad;
using google_breakpad::CrashGenerationServer;

static int server_fd = -1, client_fd = -1;
#endif

namespace
{
#if defined(USE_GOOGLE_BREAKPAD)
/*
    bool breakpadCallback(const MinidumpDescriptor& descriptor,void* context, bool succeeded)
    {
        Q_UNUSED(descriptor);
        Q_UNUSED(context);

        write(1, descriptor.path(), 50);
        write(1, "\n", 2);

        kill(-server_pid, SIGTERM);
        sleep(2);
        kill(-server_pid, SIGKILL);
        return succeeded;
    }
*/
    void setupSignalHandlers()
    {
        new ExceptionHandler(MinidumpDescriptor("/opt/minidumps"),
                             NULL,
                             NULL, //MinidumpCallback is useless
                             NULL,
                             true,
                             client_fd);
    }

    bool setup_pipe()
    {
        // Setup client/server sockets
        if (!CrashGenerationServer::CreateReportChannel(&server_fd, &client_fd))
        {
            qDebug() << "Client: CreateReportChannel failed!\n";
            return false;
        }
        return true;
    }


    bool start_server(const char* server_path_str)
    {
        qDebug() << "Client: entering startServer\n";

        // Launch handler
        int fds[2];
        if (pipe(fds) == -1)
        {
            qDebug() << "Client: pipe failed!\n";
            return false;
        }

        pid_t server_pid = fork();
        if (server_pid == 0)
        {
            qDebug() << "Client: in child after fork\n";
            // Pass the pipe fd and server fd as arguments.
            char pipe_fd_string[8];
            sprintf(pipe_fd_string, "%d", fds[1]);

            char server_fd_string[8];
            sprintf(server_fd_string, "%d", server_fd);

            char* const argv[] = {strdup(server_path_str),
                                         pipe_fd_string,
                                         server_fd_string,
                                         NULL
                                 };

            execv(server_path_str, argv);
            qDebug() << "Client: execv failed\n";
            exit(1);
        }

        // Wait for server to unblock us.
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fds[0];
        pfd.events = POLLIN | POLLERR;

        int r = HANDLE_EINTR(poll(&pfd, 1, 5000));
        if (r != 1 || (pfd.revents & POLLIN) != POLLIN)
        {
            qDebug() << "Client: poll failed?\n";
            if (pfd.revents & POLLERR)
            {
                qDebug() << "Client: POLLERR\n";
            }
            if (pfd.revents & POLLHUP)
            {
                qDebug() << "Client: POLLHUP\n";
            }
            if (pfd.revents & POLLNVAL)
            {
                qDebug() << "Client: POLLNVAL\n";
            }
            return false;
        }

        qDebug() << "Client: Poll result: " << r << "\n";
        uint8_t junk;
        read(fds[0], &junk, sizeof(junk));
        close(fds[0]);

        qDebug() << "Client: exiting startServer\n";

        return true;
    }

#else
    void signalHandler(int signum)
    {
        switch (signum)
        {
            #define ONCASE(x) case x: qDebug() << "Caught signal" << #x; break
            ONCASE(SIGINT);
            ONCASE(SIGQUIT);
            ONCASE(SIGILL);
            ONCASE(SIGABRT);
            ONCASE(SIGFPE);
            ONCASE(SIGSEGV);
            ONCASE(SIGTERM);
            #undef ONCASE
            default: qDebug() << "Caught unknown signal %d" << signum; break;
        }
        QCoreApplication *coreApp = QCoreApplication::instance();
        if( NULL != coreApp )
            coreApp->exit( signum );
        // restore default handler
        signal(signum, SIG_DFL);
        // send the signal to the default signal handler, to allow a debugger to trap it
        kill(getpid(), signum);
    }

    void setupSingalHandlers()
    {
        signal(SIGINT,  signalHandler);
        signal(SIGQUIT, signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGILL,  signalHandler);
        signal(SIGABRT, signalHandler);
        signal(SIGFPE,  signalHandler);
        signal(SIGSEGV, signalHandler);
    }
#endif
}


int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    qDebug() << "Client: started\n";

#if defined(USE_GOOGLE_BREAKPAD)
    if (!setup_pipe())
    {
        qDebug() << "Client: Pipe setup failed!\n";
        return 1;
    }

    //TODO: change into env variable
    //"-pc" - is a suffix for PC build
    QString app_path = app.applicationDirPath()+"/server-pc";
    if (!start_server(app_path.toLocal8Bit().data()))
    {
        qDebug() << "Client: Server did not start!\n";
        return 1;
    }
#endif

    setupSignalHandlers();

    //TODO: change into app input parameter
    const int NUMBER_OF_THREADS = 50;

    QList<CrashingThread*> threads;
    for (int i = 1; i <= NUMBER_OF_THREADS; ++i)
    {
        CrashingThread *thread = new CrashingThread(&app);
        thread->setThreadNumber(i);
        threads << thread;
    }

    foreach (CrashingThread *thread, threads)
    {
        thread->start();
    }

    foreach (CrashingThread *thread, threads)
    {
        thread->wait();
    }

    return app.exec();
}
