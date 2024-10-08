 /*
  * Copyright (C) 2013 Glyptodon LLC
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in
  * all copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  * THE SOFTWARE.
  */

 #include "config.h"

 #include "client.h"
 #include "guac_sftp.h"
 #include "guac_ssh.h"
 #include "sftp.h"
 #include "terminal.h"

 #ifdef ENABLE_SSH_AGENT
 #include "ssh_agent.h"
 #endif

 #include <libssh2.h>
 #include <libssh2_sftp.h>
 #include <guacamole/client.h>
 #include <guacamole/protocol.h>
 #include <guacamole/socket.h>
 #include <openssl/err.h>
 #include <openssl/ssl.h>

 #ifdef LIBSSH2_USES_GCRYPT
 #include <gcrypt.h>
 #endif

 #include <errno.h>
 #include <netdb.h>
 #include <netinet/in.h>
 #include <pthread.h>
 #include <stdbool.h>
 #include <stddef.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/select.h>
 #include <sys/socket.h>
 #include <sys/time.h>

 /**
  * Produces a new user object containing a username and password or private
  * key, prompting the user as necessary to obtain that information.
  *
  * @param client
  *     The Guacamole client containing any existing user data, as well as the
  *     terminal to use when prompting the user.
  *
  * @return
  *     A new user object containing the user's username and other credentials.
  */
 static guac_common_ssh_user* guac_ssh_get_user(guac_client* client) {

     ssh_guac_client_data* client_data = (ssh_guac_client_data*) client->data;

     guac_common_ssh_user* user;

     /* Get username */
     if (client_data->username[0] == 0)
         guac_terminal_prompt(client_data->term, "Login as: ",
                 client_data->username, sizeof(client_data->username), true);

     /* Create user object from username */
     user = guac_common_ssh_create_user(client_data->username);

     /* If key specified, import */
     if (client_data->key_base64[0] != 0) {

         guac_client_log(client, GUAC_LOG_DEBUG,
                 "Attempting private key import (WITHOUT passphrase)");

         /* Attempt to read key without passphrase */
         if (guac_common_ssh_user_import_key(user,
                     client_data->key_base64, NULL)) {

             /* Log failure of initial attempt */
             guac_client_log(client, GUAC_LOG_DEBUG,
                     "Initial import failed: %s",
                     guac_common_ssh_key_error());

             guac_client_log(client, GUAC_LOG_DEBUG,
                     "Re-attempting private key import (WITH passphrase)");

             /* Prompt for passphrase if missing */
             if (client_data->key_passphrase[0] == 0)
                 guac_terminal_prompt(client_data->term, "Key passphrase: ",
                         client_data->key_passphrase,
                         sizeof(client_data->key_passphrase), false);

             /* Reattempt import with passphrase */
             if (guac_common_ssh_user_import_key(user,
                         client_data->key_base64,
                         client_data->key_passphrase)) {

                 /* If still failing, give up */
                 guac_client_abort(client,
                         GUAC_PROTOCOL_STATUS_CLIENT_UNAUTHORIZED,
                         "Auth key import failed: %s",
                         guac_common_ssh_key_error());

                 guac_common_ssh_destroy_user(user);
                 return NULL;

             }

         } /* end decrypt key with passphrase */

         /* Success */
         guac_client_log(client, GUAC_LOG_INFO,
                 "Auth key successfully imported.");

     } /* end if key given */

     /* Otherwise, use password */
     else {

         /* Get password if not provided */
         if (client_data->password[0] == 0)
             guac_terminal_prompt(client_data->term, "Password: ",
                     client_data->password, sizeof(client_data->password),
                     false);

         /* Set provided password */
         guac_common_ssh_user_set_password(user, client_data->password);

     }

     /* Clear screen of any prompts */
     guac_terminal_printf(client_data->term, "\x1B[H\x1B[J");

     return user;

 }

 void* ssh_input_thread(void* data) {

     guac_client* client = (guac_client*) data;
     ssh_guac_client_data* client_data = (ssh_guac_client_data*) client->data;

     char buffer[8192];
     int bytes_read;

     /* Write all data read */
     while ((bytes_read = guac_terminal_read_stdin(client_data->term, buffer, sizeof(buffer))) > 0) {
         pthread_mutex_lock(&(client_data->term_channel_lock));
         libssh2_channel_write(client_data->term_channel, buffer, bytes_read);
         pthread_mutex_unlock(&(client_data->term_channel_lock));
     }

     return NULL;

 }

 void* ssh_client_thread(void* data) {
 
     guac_client* client = (guac_client*) data;
     ssh_guac_client_data* client_data = (ssh_guac_client_data*) client->data;
 
     guac_socket* socket = client->socket;
     char buffer[8192];
 
     pthread_t input_thread;
 
     /* Init SSH base libraries */
     if (guac_common_ssh_init(client))
         return NULL;
 
     /* Get user and credentials */
     client_data->user = guac_ssh_get_user(client);
 
     /* Ensure enough space in name buffer */
     char name[1024];
     size_t name_len = snprintf(name, sizeof(name), "%s@%s",
             client_data->username, client_data->hostname);
 
     /* Check if name was truncated */
     if (name_len >= sizeof(name)) {
         guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR,
                 "Username and hostname are too long.");
         return NULL;
     }
 
     /* Send new name */
     guac_protocol_send_name(socket, name);
 
     /* Open SSH session */
     client_data->session = guac_common_ssh_create_session(client,
             client_data->hostname, client_data->port, client_data->user);
     if (client_data->session == NULL) {
         /* Already aborted within guac_common_ssh_create_session() */
         return NULL;
     }
 
     pthread_mutex_init(&client_data->term_channel_lock, NULL);
 
     /* Open channel for terminal */
     client_data->term_channel =
         libssh2_channel_open_session(client_data->session->session);
     if (client_data->term_channel == NULL) {
         guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
                 "Unable to open terminal channel.");
         return NULL;
     }
 
 #ifdef ENABLE_SSH_AGENT
     /* Start SSH agent forwarding, if enabled */
     if (client_data->enable_agent) {
         libssh2_session_callback_set(client_data->session,
                 LIBSSH2_CALLBACK_AUTH_AGENT, (void*) ssh_auth_agent_callback);
 
         /* Request agent forwarding */
         if (libssh2_channel_request_auth_agent(client_data->term_channel))
             guac_client_log(client, GUAC_LOG_ERROR, "Agent forwarding request failed");
         else
             guac_client_log(client, GUAC_LOG_INFO, "Agent forwarding enabled.");
     }
 
     client_data->auth_agent = NULL;
 #endif
 
     /* Start SFTP session as well, if enabled */
     if (client_data->enable_sftp) {
 
         /* Create SSH session specific for SFTP */
         guac_client_log(client, GUAC_LOG_DEBUG, "Reconnecting for SFTP...");
         client_data->sftp_session =
             guac_common_ssh_create_session(client, client_data->hostname,
                     client_data->port, client_data->user);
         if (client_data->sftp_session == NULL) {
             /* Already aborted within guac_common_ssh_create_session() */
             return NULL;
         }
 
         /* Request SFTP */
         client_data->sftp_filesystem =
             guac_common_ssh_create_sftp_filesystem(
                     client_data->sftp_session, "/");
 
         /* Set generic (non-filesystem) file upload handler */
         client->file_handler = guac_sftp_file_handler;
 
         /* Init handlers for Guacamole-specific console codes */
         client_data->term->upload_path_handler = guac_sftp_set_upload_path;
         client_data->term->file_download_handler = guac_sftp_download_file;
 
         guac_client_log(client, GUAC_LOG_DEBUG, "SFTP session initialized");
 
     }
 
     /* Request PTY */
     if (libssh2_channel_request_pty_ex(client_data->term_channel, "linux", sizeof("linux")-1, NULL, 0,
             client_data->term->term_width, client_data->term->term_height, 0, 0)) {
         guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR, "Unable to allocate PTY.");
         return NULL;
     }
 
     /* If a command is specified, run that instead of a shell */
     if (client_data->command != NULL) {
         if (libssh2_channel_exec(client_data->term_channel, client_data->command)) {
             guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
                     "Unable to execute command.");
             return NULL;
         }
     }
 
     /* Otherwise, request a shell */
     else if (libssh2_channel_shell(client_data->term_channel)) {
         guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
                 "Unable to associate shell with PTY.");
         return NULL;
     }
 
     /* Logged in */
     guac_client_log(client, GUAC_LOG_INFO, "SSH connection successful.");
 
     /* Start input thread */
     if (pthread_create(&(input_thread), NULL, ssh_input_thread, (void*) client)) {
         guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR, "Unable to start input thread");
         return NULL;
     }
 
     /* Set non-blocking */
     libssh2_session_set_blocking(client_data->session->session, 0);
 
     /* While data available, write to terminal */
     int bytes_read = 0;
     for (;;) {
 
         /* Track total amount of data read */
         int total_read = 0;
 
         pthread_mutex_lock(&(client_data->term_channel_lock));
 
         /* Stop reading at EOF */
         if (libssh2_channel_eof(client_data->term_channel)) {
             pthread_mutex_unlock(&(client_data->term_channel_lock));
             break;
         }
 
         /* Read terminal data */
         bytes_read = libssh2_channel_read(client_data->term_channel,
                 buffer, sizeof(buffer));
 
         pthread_mutex_unlock(&(client_data->term_channel_lock));
 
         /* Attempt to write data received. Exit on failure. */
         if (bytes_read > 0) {
             int written = guac_terminal_write_stdout(client_data->term, buffer, bytes_read);
             if (written < 0)
                 break;
 
             total_read += bytes_read;
         }
 
         else if (bytes_read < 0 && bytes_read != LIBSSH2_ERROR_EAGAIN)
             break;
 
 #ifdef ENABLE_SSH_AGENT
         /* If agent open, handle any agent packets */
         if (client_data->auth_agent != NULL) {
             bytes_read = ssh_auth_agent_read(client_data->auth_agent);
             if (bytes_read > 0)
                 total_read += bytes_read;
             else if (bytes_read < 0 && bytes_read != LIBSSH2_ERROR_EAGAIN)
                 client_data->auth_agent = NULL;
         }
 #endif
 
         /* Wait for more data if reads turn up empty */
         if (total_read == 0) {
             fd_set fds;
             struct timeval timeout;
 
             FD_ZERO(&fds);
             FD_SET(client_data->session->fd, &fds);
 
             /* Wait for one second */
             timeout.tv_sec = 1;
             timeout.tv_usec = 0;
 
             if (select(client_data->session->fd + 1, &fds,
                         NULL, NULL, &timeout) < 0)
                 break;
         }
 
     }
 
     /* Kill client and Wait for input thread to die */
     guac_client_stop(client);
     pthread_join(input_thread, NULL);
 
     pthread_mutex_destroy(&client_data->term_channel_lock);
 
     guac_client_log(client, GUAC_LOG_INFO, "SSH connection ended.");
     return NULL;
 }
