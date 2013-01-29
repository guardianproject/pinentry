/* pinentry-curses.c - A secure curses dialog for PIN entry.
   Copyright (C) 2012 Abel Luck <abel@guardianproject.info>
   Copyright (C) 2002 g10 Code GmbH

   This file is part of PINENTRY.

   PINENTRY is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   PINENTRY is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <android/log.h>

#include "pinentry.h"
#include "pinentry-curses.h"

#define SOCKET_NAME "info.guardianproject.gpg.pinentry"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG , "PE-HELPER", __VA_ARGS__)
#define MSG_CMSG_CLOEXEC NULL


int send_fd(int socket, int fd_to_send)
 {
  struct msghdr socket_message;
  struct iovec io_vector[1];
  struct cmsghdr *control_message = NULL;
  char message_buffer[1];
  /* storage space needed for an ancillary element with a paylod of length is CMSG_SPACE(sizeof(length)) */
  char ancillary_element_buffer[CMSG_SPACE(sizeof(int))];
  int available_ancillary_element_buffer_space;

  /* at least one vector of one byte must be sent */
  message_buffer[0] = 'F';
  io_vector[0].iov_base = message_buffer;
  io_vector[0].iov_len = 1;

  /* initialize socket message */
  memset(&socket_message, 0, sizeof(struct msghdr));
  socket_message.msg_iov = io_vector;
  socket_message.msg_iovlen = 1;

  /* provide space for the ancillary data */
  available_ancillary_element_buffer_space = CMSG_SPACE(sizeof(int));
  memset(ancillary_element_buffer, 0, available_ancillary_element_buffer_space);
  socket_message.msg_control = ancillary_element_buffer;
  socket_message.msg_controllen = available_ancillary_element_buffer_space;

  /* initialize a single ancillary data element for fd passing */
  control_message = CMSG_FIRSTHDR(&socket_message);
  control_message->cmsg_level = SOL_SOCKET;
  control_message->cmsg_type = SCM_RIGHTS;
  control_message->cmsg_len = CMSG_LEN(sizeof(int));
  *((int *) CMSG_DATA(control_message)) = fd_to_send;

  return sendmsg(socket, &socket_message, 0);
 }


 int recv_fd(int socket)
 {
  int sent_fd, available_ancillary_element_buffer_space;
  struct msghdr socket_message;
  struct iovec io_vector[1];
  struct cmsghdr *control_message = NULL;
  char message_buffer[1];
  char ancillary_element_buffer[CMSG_SPACE(sizeof(int))];

  /* start clean */
  memset(&socket_message, 0, sizeof(struct msghdr));
  memset(ancillary_element_buffer, 0, CMSG_SPACE(sizeof(int)));

  /* setup a place to fill in message contents */
  io_vector[0].iov_base = message_buffer;
  io_vector[0].iov_len = 1;
  socket_message.msg_iov = io_vector;
  socket_message.msg_iovlen = 1;

  /* provide space for the ancillary data */
  socket_message.msg_control = ancillary_element_buffer;
  socket_message.msg_controllen = CMSG_SPACE(sizeof(int));

  // TODO: the NULL below used ot be msg_cmsg_cloexec
  // but it broke compilation on android, make sure this isn't killing puppies
  if(recvmsg(socket, &socket_message, MSG_CMSG_CLOEXEC) < 0)
   return -1;

  if(message_buffer[0] != 'F')
  {
   /* this did not originate from the above function */
   return -1;
  }

  if((socket_message.msg_flags & MSG_CTRUNC) == MSG_CTRUNC)
  {
   /* we did not provide enough space for the ancillary element array */
   return -1;
  }

  /* iterate ancillary elements */
   for(control_message = CMSG_FIRSTHDR(&socket_message);
       control_message != NULL;
       control_message = CMSG_NXTHDR(&socket_message, control_message))
  {
   if( (control_message->cmsg_level == SOL_SOCKET) &&
       (control_message->cmsg_type == SCM_RIGHTS) )
   {
    sent_fd = *((int *) CMSG_DATA(control_message));
    return sent_fd;
   }
  }

  return -1;
 }


int send_intent() {

  char command[PATH_MAX];

  sprintf(command, "/system/bin/am start -n info.guardianproject.gpg/info.guardianproject.gpg.PinEntryActivity");

      static const char* const unsec_vars[] = {
        "GCONV_PATH",
        "GETCONF_DIR",
        "HOSTALIASES",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_DYNAMIC_WEAK",
        "LD_LIBRARY_PATH",
        "LD_ORIGIN_PATH",
        "LD_PRELOAD",
        "LD_PROFILE",
        "LD_SHOW_AUXV",
        "LD_USE_LOAD_BIAS",
        "LOCALDOMAIN",
        "LOCPATH",
        "MALLOC_TRACE",
        "MALLOC_CHECK_",
        "NIS_PATH",
        "NLSPATH",
        "RESOLV_HOST_CONF",
        "RES_OPTIONS",
        "TMPDIR",
        "TZDIR",
        "LD_AOUT_LIBRARY_PATH",
        "LD_AOUT_PRELOAD",
        // not listed in linker, used due to system() call
        "IFS",
    };
    const char* const* cp = unsec_vars;
    const char* const* endp = cp + sizeof(unsec_vars)/sizeof(unsec_vars[0]);
    while (cp < endp) {
        unsetenv(*cp);
        cp++;
    }
    // sane value so "am" works
    setenv("LD_LIBRARY_PATH", "/vendor/lib:/system/lib", 1);
    setegid(getgid());
    seteuid(getuid());
    return system(command);
}

int exec_dialog() {
    /* 1. launch pinentry activity */
  send_intent();
  //sleep(1); // TODO find better way to detect if activity is launched

  /* 2. connect to activity's socket */
  struct sockaddr_un addr;
  int fd;

  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  strncpy( &addr.sun_path[1], SOCKET_NAME, sizeof(addr.sun_path)-1 );
  /* calculate the length of our addrlen, for some reason this isn't simply
   * sizeof(addr), TODO: learn why, i suspect it has something to do with sun_path
   * being a char[108]
   */
  int len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(&addr.sun_path[1]);

  if (bind(fd, (struct sockaddr*) &addr, len) == -1) {
    perror("bind error");
    exit(-1);
  }

  if (listen(fd, 5) == -1) {
    perror("listen error");
    exit(-1);
  }
  
    LOGD("waiting for connection\n");
     if ( (fd = accept(fd, NULL, NULL)) == -1) {
      perror("accept error");
      exit(1);
    }

//   if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
//     perror("connect error");
//     exit(-1);
//   }

  LOGD("connection established\n");
  return fd;
}

int
android_cmd_handler (pinentry_t pe)
{
    LOGD("android_cmd_handler: sup?\n");
    int want_pass = pe->pin;
    if (want_pass)
    {
        LOGD("android_cmd_handler: i think they want a pin..\n");
        
        const char *pin = "1234";
        int len = strlen (pin);
        pinentry_setbufferlen (pe, len + 1);
        strcpy (pe->pin, pin);
        return len;
    }
    return 0;
}

pinentry_cmd_handler_t pinentry_cmd_handler = android_cmd_handler;


int main (int argc, char *argv[])
{
  LOGD("Welcome to pinentry-android\n");
  int fd, rc;
  
  fd = exec_dialog();
  if ( fd == -1 ) {
      LOGD("Java fd is -1, bailing\n");
      exit(-1);
  }
    rc = send_fd(fd, STDIN_FILENO);
    if (rc == -1) {
        LOGD("sending STDIN failed\n");
        exit(-1);
    }
    rc = send_fd(fd, STDOUT_FILENO);
    if (rc == -1) {
        LOGD("sending STDOUT failed\n");
        exit(-1);
    }

    LOGD("successfully sent my fds to javaland\n");
    char buf[1];
    int r = read(fd, buf, 1);
    if( r == 1 )
        return r;
    return -1; // UNKNOWN WTF
  /*pinentry_init ("pinentry-android");

  /* Consumes all arguments.  *
  if (pinentry_parse_opts (argc, argv))
    {
      printf ("pinentry-android (pinentry) " VERSION "\n");
      exit (EXIT_SUCCESS);
    }(*/
}
