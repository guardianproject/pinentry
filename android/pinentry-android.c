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
#include <stdarg.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <paths.h>
#include <pwd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android/log.h>

#include "pinentry.h"
#include "pinentry-curses.h"

#define GPG_APP_PATH "/data/data/info.guardianproject.gpg"

#define INTERNAL_GNUPGHOME GPG_APP_PATH "/app_home"
#define EXTERNAL_GNUPGHOME GPG_APP_PATH "/app_gnupghome"

#define ACTION_PINENTRY "start -n info.guardianproject.gpg/info.guardianproject.gpg.pinentry.PinEntryActivity --activity-no-history --activity-clear-top"

#define SOCKET_HELPER "info.guardianproject.gpg.pinentryhelper"
#define SOCKET_PINENTRY "info.guardianproject.gpg.pinentry"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG , "PE-HELPER", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR , "PE-HELPER", __VA_ARGS__)

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

static int socket_create(char *path, size_t len) {
    int fd;
    struct sockaddr_un sun;

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
        LOGE ( "socket_create: socket error" );
        return -1;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        LOGE(": fcntl FD_CLOEXEC");
        goto err;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_LOCAL;
    snprintf(path, len, "%s/S.pinentry", INTERNAL_GNUPGHOME);
    memset(sun.sun_path, 0, sizeof(sun.sun_path));
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);

    /*
     * Delete the socket to protect from situations when
     * something bad occured previously and the kernel reused pid from that process.
     * Small probability, isn't it.
     */
    unlink(sun.sun_path);

    if (bind(fd, (struct sockaddr*)&sun, sizeof(sun)) < 0) {
        LOGE("bind error");
        goto err;
    }

    if (listen(fd, 1) < 0) {
        LOGE("listen error");
        goto err;
    }

    return fd;
err:
    close(fd);
    return -1;
}

static int socket_accept( int sock ) {
    struct timeval tv;
    fd_set fds;
    int fd, rc;

    tv.tv_sec = 30;
    tv.tv_usec = 0;
    FD_ZERO( &fds );
    FD_SET( sock, &fds );

    do {
        rc = select( sock + 1, &fds, NULL, NULL, &tv );
    } while ( rc < 0 && errno == EINTR );
    if ( rc < 1 ) {
        LOGE( "select" );
        return -1;
    }

    fd = accept( sock, NULL, NULL );
    if ( fd < 0 ) {
        LOGE( "accept" );
        return -1;
    }

    return fd;
}

/*
 * sends stdin and stdout over the socket
 * in that order, returns 0 on success
 */
static int socket_send_sdtio( int fd ) {
    if ( send_fd ( fd, STDIN_FILENO ) < 0  ) {
        LOGE ( "sending STDIN failed\n" );
        return -1;
    }

    if ( send_fd ( fd, STDOUT_FILENO ) < 0 ) {
        LOGE ( "sending STDOUT failed\n" );
        return -1;
    }
    return 0;
}

/*
 * Block until EOF or data is receied from the fd
 * If data is received, one byte is read and returned
 */
static int socket_wait(int fd) {
    struct pollfd fds[1];
    char buf[1];
    int rc = 0;

    fds[0].fd = fd;
    fds[0].events = POLLIN;

    rc = poll(fds, 1, -1);
    LOGD("socket_wait: poll returned");
    if( rc == -1 ) {

        LOGE("socket_wait: poll error");
        return -1;
    } else if( fds[0].revents & POLLIN ) {

        LOGD("socket_wait: input from pinentry\n");
        rc = read ( fd, buf, 1 );
        if( rc == 1 ) {
            rc = buf[0];
            LOGD ( "socket_wait: exit rc=%d\n", rc );
            return rc;
        }
        return -1; // EOF
    }
    LOGD("socket_wait: unknown state");
    return -1;
}

static void socket_cleanup(const char* sock_path) {
    if (sock_path[0]) {
        if (unlink(sock_path))
            LOGE("unlink failed for: %s", sock_path);
    }
}

void start_internal_server ( void ) {
    char sock_path[PATH_MAX];
    int sock_serv, sock_client;
    sock_serv = socket_create( sock_path, sizeof( sock_path ) );
    LOGD( "start_internal_server: %s", sock_path );

    if( sock_serv < 0 ) {
        LOGE( "start_internal_server: sock_serv error" );
        goto error;
    }

    sock_client = socket_accept( sock_serv );

    if( sock_client < 0 ) {
        LOGE( "start_internal_server: sock_client error" );
        goto error;
    }

    if( socket_send_sdtio(sock_client) != 0 ) {
        LOGE("sending stdio failed");
        goto error;
    }

    // gpg-agent and the real pinentry are now communicating
    // but our process must stay alive until they're finished
    // so we can exit with the actual return code
    int rc = socket_wait(sock_client);

    socket_cleanup(sock_path);
    exit( rc );
error:
    socket_cleanup(sock_path);
    exit( EXIT_FAILURE );
}
#if 0
// We used to connect to connect to java over a domain socket
// to launch the pinentry activity, but now we use the am command
// this method might need to be ressurected in the future

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
#endif

void sanitize_env( void ) {
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
        "IFS",
    };
    const char* const* cp   = unsec_vars;
    const char* const* endp = cp + sizeof(unsec_vars)/sizeof(unsec_vars[0]);
    while (cp < endp) {
        unsetenv(*cp);
        cp++;
    }
    setenv("LD_LIBRARY_PATH", "/vendor/lib:/system/vendor/lib:/system/lib", 0);
    setenv("BOOTCLASSPATH", "/system/framework/core.jar:/system/framework/core-junit.jar:/system/framework/bouncycastle.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/telephony-common.jar:/system/framework/mms-common.jar:/system/framework/android.policy.jar:/system/framework/services.jar:/system/framework/apache-xml.jar", 1);
}

/*
 * detect the user_id which is new in 4.2
 * as part of the multiuser mode feature
 * untested, but should work ;-)
 * 
 * -> someone want to send me a multiuser device?
 * 
 * Pre ICS, the android_user_id = 0
 * Post ICS, the formula is as follows
 *   M*100,000 + 10,000+N = linux_uid
 * where,
 *   N = app id, offset from 10,000
 *   M = android user id (human users), starting at 0
 * 
 * using integer division:
 *     android_user_id = linux_uid / 100000
 *              app_id = linux_uid % 100000
 *                 linux_uid = android_user_id * 100000 + (app_id % 100000)
 */ 
static unsigned int get_android_user_id( void ) {
    unsigned int uid = getuid();
    unsigned int android_user_id = 0;
    if( uid > 99999 ) {
        android_user_id = uid / 100000;
    }
    return android_user_id;
}

/*
 * Exec the provided command in a new process
 * and send all output to /dev/null
 */
static int run_command(char* command) {
    char *wrapper[] = { "sh", "-c", command, NULL, };

    pid_t pid = fork();
    if( pid < 0 ) {
        return -1;
    } else if( pid > 0 ) {
        return 0;
    }

    LOGD ( "run_command:  %s", command );
    // quiet mode
    int devzero = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    dup2(devzero, 0);
    dup2(devnull, 1);
    dup2(devnull, 2);

    execv(_PATH_BSHELL, wrapper);
    LOGE("run_command execv failed");
    exit(EXIT_FAILURE);
}

/*
 * Uses the 'am start' utility in android to send an ASYNC request
 * to launch the PinentryActivity.
 * The activity is not guaranteed to have been started.
 */
static int launch_pinentry_gui( void ) {
    char command[ARG_MAX];
    unsigned int android_user_id = get_android_user_id();

    snprintf(command, sizeof(command), "exec /system/bin/am " ACTION_PINENTRY " --user %d", android_user_id);
    LOGD ( "sending intent with: %s", command );
    return run_command(command);
}

int main ( int argc, char *argv[] ) {

    sanitize_env();
    struct stat gpg_stat;

    /* Consumes all arguments.  */
    if ( pinentry_parse_opts ( argc, argv ) ) {
        printf ( "pinentry-android (pinentry) " VERSION "\n" );
        exit ( EXIT_SUCCESS );
    }

    LOGD ( "Welcome to pinentry-android\n" );

    // is gnupg even installed?
    if (stat(GPG_APP_PATH, &gpg_stat) < 0) {
        LOGE("gpg not installed" GPG_APP_PATH);
        exit ( EXIT_FAILURE );
    }

    /*
     * Launch the Android GUI component asyncronously
     */
    if( launch_pinentry_gui() < 0 ) {
        LOGE( "launching activity failed" );
        exit ( EXIT_FAILURE );
    }

    LOGD( "gpg_stat.st_uid(%lu) == getuid(%d)", gpg_stat.st_uid, getuid());

    if( gpg_stat.st_uid == getuid() ) {
        // internal pinentry
        // this pinentry process has been invoked
        // by the gnupg-for-android app
        LOGD( "internal pinentry" );
        start_internal_server(); // never returns
        exit ( EXIT_FAILURE );
    } else {
        // TODO external pinentry
        // some other application wants to access pinentry
        // NYI
        LOGE( "NYI - external pinentry request from app %d", getuid() );
        exit ( EXIT_FAILURE );
    }
    return -1;
}
