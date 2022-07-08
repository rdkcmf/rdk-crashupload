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

#include <assert.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#ifdef YOCTO_BUILD
#include "secure_wrapper.h"
#endif

/**
 * @defgroup Crashupload Crashupload
 *
 * - Crashupload component helps to upload coredump and minidump files (crashes) that happened in the STBs to the crash portal server.
 * - The crash portal processes these crash dumps and logs and provides a meaningful backtrace.
 * - Whenever the crash happens STB will create a minidump file with ".dmp" extention at configured path(for ex: /minidumps/).
 * - Then this dump file will be converted into tar file before getting uploaded to the RDK crash portal.
 * - This tar file has a naming convention as build-id_mac_date_box<type_device-model_dumpfilenumber.dmp.tgz.
 * - It is possible to download this "*.dmp.tgz" file directly from the RDK crash portal using MAC address of the device
 *   and filters to see minidump report and to download this file.
 * - It contains dump file and some log files like version.txt and core_log.txt.
 * - The RDK crash portal url at which dump file gets upload can be configured in uploadDumps.sh script file in the box.
 *
 * @defgroup Crashupload_API Crashupload Public APIs
 * @ingroup Crashupload
 *
 */

#ifdef __GNUC__
#  define ALIGNAS(TYPE) __attribute__ ((aligned(__alignof__(TYPE))))
#else
#  define ALIGNAS(TYPE) /* empty */
#endif

static volatile int interrupted = 0;


/**
 * @addtogroup Crashupload_API
 * @{
 */

/**
 * @brief Signal Handler function.
 *
 * @param[in] s Signal Type
 *
 */

static void
process_interrupt_handler(const int s)
{
  if (s == SIGINT)
    interrupted = 1;
}

/**
 * @brief This API notifies whether dump is generated in the minidump directory and triggers the
 * upload dump script to upload the files to server.
 *
 * @param[in] directory          Directory name
 * @param[in] command_to_run     Shell script to execute
 * @param[in] command_args       Arguments for shell script
 * @param[in] patterns           Pattern to verify, Patterns can be *.dmp, *.cmd etc.
 * @param[in] pattern_count      Number of patterns to be verified.
 */

static int
directory_watcher(const char *const directory,
                  const char* command_to_run,
                  const char* command_args,
                  const char *const *const patterns,
                  const size_t pattern_count)
{
     int notifyfd = -1;
     int watchfd = -1;
     int ret = 0;
     const char * errmsg = "unknown error";

     notifyfd = inotify_init();
     if (notifyfd < 0)
     {
         errmsg = "inotify_init";
         goto catch;
     }
     watchfd = inotify_add_watch(notifyfd, directory, IN_CREATE);
     if (watchfd < 0)
     {
          errmsg = "inotify_add_watch";
          goto catch;
     }
     while (1)
     {
          char buffer[sizeof(struct inotify_event) + NAME_MAX + 1] ALIGNAS(struct inotify_event) = {0};
          const struct inotify_event * event_ptr;
          /* coverity fix CID: 136730 */
          ssize_t count = read(notifyfd, buffer, (sizeof(buffer) - 1));
          if (count < 0)
          {
             if (interrupted)
                 goto finally;
             errmsg = "read";
             goto catch;
          }
          event_ptr = (const struct inotify_event *) buffer;
          assert(event_ptr->wd == watchfd);
          assert(event_ptr->mask & IN_CREATE);
          if (event_ptr->len)
          {
             size_t i;
             for (i = 0; i < pattern_count; ++i)
             {
              switch (fnmatch(patterns[i], event_ptr->name, FNM_PATHNAME))
                {
                case 0:
                  /* Your application logic here... */
                  if (printf("%s\n", event_ptr->name) < 0)
                    {
                      errmsg = "printf";
                      goto catch;
                    }
                  else
                    {
                        /* Exit from wait if the command to run is NULL */
                        if(strncmp(command_to_run,"NULL",4) == 0){
                              printf("Flag file is created. Exiting from wait \n");
                              goto finally;
                        }
                        printf("Calling the binary %s\n",command_to_run);
#ifdef YOCTO_BUILD
                        v_secure_system("sh -c '%s %s'",command_to_run,command_args);
#else
                        char command[50];

                        if(command_to_run == NULL || command_args == NULL)
                        {
                           errmsg = "NULL";
                           goto catch;
                        }

                        if (sizeof(command) <=  (strlen(command_to_run)+strlen(command_args)+strlen("ssh -c ' '")))
                        {
                           errmsg = "command buffer overflow";
                           goto catch;
                        }
                        sprintf(command,"sh -c '%s %s'",command_to_run,command_args);

                        system(command);
#endif
                        printf("The script /lib/rdk/uploadDumps.sh execution completed..!");
                    }
                  break;
                case FNM_NOMATCH:
                  break;
                default:
                  errmsg = "fnmatch";
                  goto catch;
                }
             }
          }
       } 
  finally:
  if (watchfd >= 0)
  {
      int status = close(watchfd);
      watchfd = -1;
      if (status < 0)
        {
          errmsg = "close(watchfd)";
          goto catch;
        }
  }
  if (notifyfd >= 0)
  {
      int status = close(notifyfd);
      notifyfd = -1;
      if (status < 0)
        {
          errmsg = "close(notifyfd)";
          goto catch;
        }
  }
  return ret;
  catch:
  if (errmsg && errno)
    perror(errmsg);
  ret = -1;
  goto finally;
}

/**
 * @brief Main Function.
 *
 * This binary is used to monitor the specified directory in the box and when there is a change, corresponding upload script will kick in
 * and uploads the files to the server.
 *
 * Usage: /usr/bin/inotify-minidump-watcher DIRECTORY COMMAND_TO_RUN COMMAND_ARGS PATTERN
 * Eg: /usr/bin/inotify-minidump-watcher /minidumps /lib/rdk/uploadDumps.sh "" 0 *.dmp
*/

int
main(const int argc, const char *const *const argv)
{
    if (argc < 5)
    {
      fprintf(stderr, "usage: %s DIRECTORY COMMAND_TO_RUN COMMAND_ARGS PATTERN...\n", argv[0]);
      return EXIT_FAILURE;
    }
  
    struct sigaction sa;
    sa.sa_handler = process_interrupt_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
  
    if (directory_watcher(argv[1], argv[2] , argv[3], argv + 4, argc - 4) < 0)
         return EXIT_FAILURE;
    
    return EXIT_SUCCESS;
}

/**
 * @} // End of Doxygen
 */

