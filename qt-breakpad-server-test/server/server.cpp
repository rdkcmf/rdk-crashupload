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
// Part of conditional implementation
//#include <pthread.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include "client/linux/crash_generation/client_info.h"
#include "client/linux/crash_generation/crash_generation_server.h"
#include "servercontainer.h"
#include <string.h>

using google_breakpad::ClientInfo;
using google_breakpad::CrashGenerationServer;

using std::string;

static string dump_path = "/opt/minidumps";

pthread_mutex_t mutex         = PTHREAD_MUTEX_INITIALIZER;

// Part of conditional implementation
//pthread_cond_t  condition_var = PTHREAD_COND_INITIALIZER;

static unsigned int count = 0;

static void OnClientDumpRequest(void* aContext,
                                const ClientInfo* aClientInfo,
                                const string* aFilePath)
{
    static const char msg[] = "Server wrote dump for client: ";
    write(2, msg, sizeof(msg)-1);
    static const char* dump_path = aFilePath->c_str();
    write(2, dump_path, strlen(dump_path));
    write(2, "\n", 1);

    // Part of conditional implementation
    //pthread_mutex_lock(&mutex);
    //pthread_cond_signal(&condition_var);
    //pthread_mutex_unlock(&mutex);
}

int main(int argc, char** argv)
{
    pid_t spid = getpid();
    printf("Server pid %d: starting\n", spid);
    const int required_args = 3;
    if (argc < required_args)
    {
        printf("usage: server: <pipe fd> <server fd>\n");
        return 1;
    }

    int pipe_fd = atoi(argv[1]);
    int server_fd = atoi(argv[2]);

    // Part of conditional implementation
    //pthread_mutex_lock(&mutex);

    ServerContainer pServer(new CrashGenerationServer(server_fd,
                                                      OnClientDumpRequest,
                                                      NULL,
                                                      NULL,
                                                      NULL,
                                                      true,
                                                      &dump_path));

    if (!pServer.get()->Start())
    {
        printf("Server pid %d: Failed to start CrashGenerationServer\n",
               spid);
        return 1;
    }

    printf("Server pid %d: started server\n", spid);

    // Signal parent that this process has started the server.
    uint8_t byte = 1;
    write(pipe_fd, &byte, sizeof(byte));

    // Part of conditional implementation
    /*
    printf("Server pid %d: waiting for client request\n", spid);
    pthread_cond_wait(&condition_var, &mutex);
    */

    while (1)
    {
        // server loop
    }

    return 0;
}
