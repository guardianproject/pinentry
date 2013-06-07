/* pinentry-curses.c - A pinentry wrapper for Android
   Copyright (C) 2013 Abel Luck <abel@guardianproject.info>
   Copyright (C) 2006-2012, C. Thomas Stover <cts at thomasstover.com>
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
#include <poll.h>

#include <android/log.h>

#include "pinentry.h"
#include "pinentry-curses.h"

#define SOCKET_HELPER "info.guardianproject.gpg.pinentryhelper"
#define SOCKET_PINENTRY "info.guardianproject.gpg.pinentry"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG , "PE-HELPER", __VA_ARGS__)

/* dummy cmd_handler to prevent linking errors */
static int
android_cmd_handler (pinentry_t pe)
{
    return pe;
}

pinentry_cmd_handler_t pinentry_cmd_handler = android_cmd_handler;

int send_fd ( int sockfd, int fd_to_send ) {
    struct msghdr socket_message;
    struct iovec io_vector[1];
    struct cmsghdr *control_message = NULL;
    char message_buffer[1];
    /* storage space needed for an ancillary element with a paylod of length is CMSG_SPACE(sizeof(length)) */
    char ancillary_element_buffer[CMSG_SPACE ( sizeof ( int ) )];
    int available_ancillary_element_buffer_space;

    /* at least one vector of one byte must be sent */
    message_buffer[0] = 'F';
    io_vector[0].iov_base = message_buffer;
    io_vector[0].iov_len = 1;

    /* initialize socket message */
    memset ( &socket_message, 0, sizeof ( struct msghdr ) );
    socket_message.msg_iov = io_vector;
    socket_message.msg_iovlen = 1;

    /* provide space for the ancillary data */
    available_ancillary_element_buffer_space = CMSG_SPACE ( sizeof ( int ) );
    memset ( ancillary_element_buffer, 0, available_ancillary_element_buffer_space );
    socket_message.msg_control = ancillary_element_buffer;
    socket_message.msg_controllen = available_ancillary_element_buffer_space;

    /* initialize a single ancillary data element for fd passing */
    control_message = CMSG_FIRSTHDR ( &socket_message );
    control_message->cmsg_level = SOL_SOCKET;
    control_message->cmsg_type = SCM_RIGHTS;
    control_message->cmsg_len = CMSG_LEN ( sizeof ( int ) );
    * ( ( int * ) CMSG_DATA ( control_message ) ) = fd_to_send;

    return sendmsg ( sockfd, &socket_message, 0 );
}

int recv_fd ( int sockfd ) {
    int sent_fd, available_ancillary_element_buffer_space;
    struct msghdr socket_message;
    struct iovec io_vector[1];
    struct cmsghdr *control_message = NULL;
    char message_buffer[1];
    char ancillary_element_buffer[CMSG_SPACE ( sizeof ( int ) )];

    /* start clean */
    memset ( &socket_message, 0, sizeof ( struct msghdr ) );
    memset ( ancillary_element_buffer, 0, CMSG_SPACE ( sizeof ( int ) ) );

    /* setup a place to fill in message contents */
    io_vector[0].iov_base = message_buffer;
    io_vector[0].iov_len = 1;
    socket_message.msg_iov = io_vector;
    socket_message.msg_iovlen = 1;

    /* provide space for the ancillary data */
    socket_message.msg_control = ancillary_element_buffer;
    socket_message.msg_controllen = CMSG_SPACE ( sizeof ( int ) );

    /* the NULL below used to be MSG_CMSG_CLOEXEC
       but it broke compilation on android */

    if ( recvmsg ( sockfd, &socket_message, NULL ) < 0 )
        return -1;

    if ( message_buffer[0] != 'F' ) {
        /* this did not originate from the above function */
        return -1;
    }

    if ( ( socket_message.msg_flags & MSG_CTRUNC ) == MSG_CTRUNC ) {
        /* we did not provide enough space for the ancillary element array */
        return -1;
    }

    /* iterate ancillary elements */
    for ( control_message = CMSG_FIRSTHDR ( &socket_message );
            control_message != NULL;
            control_message = CMSG_NXTHDR ( &socket_message, control_message ) ) {
        if ( ( control_message->cmsg_level == SOL_SOCKET ) &&
                ( control_message->cmsg_type == SCM_RIGHTS ) ) {
            sent_fd = * ( ( int * ) CMSG_DATA ( control_message ) );
            return sent_fd;
        }
    }

    return -1;
}

int start_server ( void ) {

    struct sockaddr_un addr;
    int server_fd, client_fd, addr_len;
    struct pollfd fds[1];
    int TIMEOUT = 5000;

    if ( ( server_fd = socket ( AF_UNIX, SOCK_STREAM, 0 ) ) == -1 ) {
        perror ( "socket error" );
        exit ( -1 );
    }

    memset ( &addr, 0, sizeof ( addr ) );
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy ( &addr.sun_path[1], SOCKET_PINENTRY, sizeof ( addr.sun_path )-1 );

    addr_len= offsetof ( struct sockaddr_un, sun_path ) + 1 + strlen ( &addr.sun_path[1] );
    if ( bind ( server_fd, ( struct sockaddr* ) &addr, addr_len ) == -1 ) {
        perror ( "bind error" );
        exit ( -1 );
    }

    if ( listen ( server_fd, 5 ) == -1 ) {
        perror ( "listen error" );
        exit ( -1 );
    }

    LOGD ( "waiting for connection\n" );

    fds[0].fd = server_fd;
    fds[0].events = POLLIN;

    if( poll(fds, 2, TIMEOUT) > 0 ) {
        if ( ( client_fd = accept ( server_fd, NULL, NULL ) ) == -1 ) {
            perror ( "accept error" );
            exit ( 1 );
        }
        LOGD ( "client connected\n" );
    } else {
        LOGD("accept timeout reached\n");
        client_fd = -1;
    }

    return client_fd;
}

int notify_helper ( void ) {

    struct sockaddr_un addr;
    int fd, addr_len;
    char cmd[] = "START\n";
    char buf[1];

    if ( ( fd = socket ( AF_UNIX, SOCK_STREAM, 0 ) ) == -1 ) {
        perror ( "socket error" );
        exit ( -1 );
    }

    memset ( &addr, 0, sizeof ( addr ) );
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy ( &addr.sun_path[1], SOCKET_HELPER, sizeof ( addr.sun_path )-1 );

    addr_len = offsetof ( struct sockaddr_un, sun_path ) + 1 + strlen ( &addr.sun_path[1] );
    LOGD ( "connecting to Java socket server...\n" );
    if ( connect ( fd, ( struct sockaddr* ) &addr, addr_len ) < 0 ) {
        perror ( "connect error" );
        exit ( EXIT_FAILURE );
    }

    LOGD ( "connected, launching activity\n" );

    if ( write ( fd, cmd, strlen ( cmd ) ) != strlen(cmd) ) {
        perror ( "sending start failed:" );
    }

    LOGD ( "sent start command, waiting response\n" );

    if ( read ( fd, buf, 1 ) != 1 ) {
        LOGD ( "reading response from server failed\n" );
        perror ( "server resp:" );
        exit ( EXIT_FAILURE );
    }
    if ( buf[1] == -1 ) {
        LOGD ( "launching activity failed\n" );
        exit ( EXIT_FAILURE );
    }

    LOGD ( "pinentry activity launched\n" );

    return fd;
}

int main ( int argc, char *argv[] ) {
    int pe_fd, control_fd, rc;
    char buf[1];
    int r, stop = 0;
    int TIMEOUT = 2000;
    int timeout_cnt, max_timeouts = 10;
    struct pollfd fds[2];

    char CMD_PING[] = "PING\n";

    /* Consumes all arguments.  */
    if ( pinentry_parse_opts ( argc, argv ) ) {
        printf ( "pinentry-android (pinentry) " VERSION "\n" );
        exit ( EXIT_SUCCESS );
    }

    LOGD ( "Welcome to pinentry-android\n" );

    /* First we communicate with Java
     * to launch the GUI and start pinentry listener
     */
    control_fd = notify_helper();

    /* Then we launch our own listener to handle
     * the stdin stdout handoff*/
    pe_fd = start_server();

    if ( pe_fd == -1 ) {
        LOGD ( "java fd is -1, bailing\n" );
        exit ( -1 );
    }

    rc = send_fd ( pe_fd, STDIN_FILENO );
    if ( rc == -1 ) {
        LOGD ( "sending STDIN failed\n" );
        exit ( -1 );
    }

    rc = send_fd ( pe_fd, STDOUT_FILENO );
    if ( rc == -1 ) {
        LOGD ( "sending STDOUT failed\n" );
        exit ( -1 );
    }

    LOGD ( "successfully sent my fds to javaland\n" );


    fds[0].fd = control_fd;
    fds[0].events = POLLIN;
    fds[1].fd = pe_fd;
    fds[1].events = POLLIN;
    timeout_cnt = 0;

    while(!stop) {
        LOGD ( "polling\n" );
        rc = poll(fds, 2, TIMEOUT);
        LOGD("\tpoll result %d\n",rc);
        if( rc == -1 ) {
            perror("poll:");
        } else if ( rc == 0 ) {
            LOGD("timedout.. pinging\n");
            timeout_cnt++;
            r = write(control_fd, CMD_PING, strlen(CMD_PING));
            if( r == -1 ) {
                LOGD ( "ping failed\n" );
                perror("write ping:");
            } else if (r != strlen(CMD_PING) ) {
                LOGD ( "ping failed, incomplete\n" );
            }

        } else if( fds[0].revents & POLLIN ) {
            LOGD("input from control\n");
            r = read ( control_fd, buf, 1 );
            if ( r == 1 ) {
                r = buf[0];
                switch (r) {
                    case 1: // EXIT
                        stop = 1;
                        LOGD ( "exit received\n" );
                    case 2: // PONG
                        LOGD("Pong received\n");
                    default:
                        LOGD("unknown response %d\n", r);
                }
            } else if ( r == 0 ) {
                //EOF
                LOGD("control EOF\n");
                stop = 1;
            }  else  {
                perror("control read error:");
            }
        } else if( fds[1].revents & POLLIN ) {
            LOGD("input from pinentry\n");
            r = read ( pe_fd, buf, 1 );
            if( r == 1 ) {
                r = buf[0];
                LOGD ( "exit received r=\n",r );
            } else if( r == 0 ) {
                //EOF
                LOGD("pinentry EOF\n");
            } else {
                LOGD("read from pinentry error r=%d\n", r);
                r = -1;
            }
            stop = 1;
        } else {
            LOGD("unknown state\n");
        }
    }

    LOGD ( "finishing\n" );
    return r;
}
