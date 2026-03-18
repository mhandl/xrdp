/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2013 jay.sorg@gmail.com
 * Copyright (C) Gravitational, Inc 2024
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Pre-auth smartcard certificate extraction for Teleport virtual
 * smartcard authentication.
 */

#ifndef XRDP_SMARTCARD_H
#define XRDP_SMARTCARD_H

#include "arch.h"
#include "parse.h"

struct xrdp_smartcard;

/**
 * State of the smartcard certificate extraction state machine
 */
enum xrdp_smartcard_state
{
    XRDP_SC_IDLE = 0,
    XRDP_SC_WAIT_DEVICE_ANNOUNCE,
    XRDP_SC_WAIT_ESTABLISH_CONTEXT,
    XRDP_SC_WAIT_LIST_READERS,
    XRDP_SC_WAIT_CONNECT,
    XRDP_SC_WAIT_TRANSMIT_SELECT_PIV,
    XRDP_SC_WAIT_TRANSMIT_SELECT_CERT,
    XRDP_SC_WAIT_TRANSMIT_READ_BINARY,
    XRDP_SC_WAIT_DISCONNECT,
    XRDP_SC_WAIT_RELEASE_CONTEXT,
    XRDP_SC_DONE,
    XRDP_SC_ERROR
};

/**
 * Create a new smartcard processing context
 *
 * @return Allocated smartcard context, or NULL on error
 */
struct xrdp_smartcard *
xrdp_smartcard_create(void);

/**
 * Free smartcard processing context
 *
 * @param sc Smartcard context (may be NULL)
 */
void
xrdp_smartcard_delete(struct xrdp_smartcard *sc);

/**
 * Process an incoming RDPDR smartcard IOCTL response
 *
 * @param sc Smartcard context
 * @param s Stream containing the RDPDR response data
 * @return 0 if processing should continue, 1 if cert extraction is
 *         complete, -1 on error
 */
int
xrdp_smartcard_process_rdpdr(struct xrdp_smartcard *sc,
                             struct stream *s);

/**
 * Check if a smartcard device was detected
 *
 * @param sc Smartcard context
 * @return 1 if a smartcard device is present, 0 otherwise
 */
int
xrdp_smartcard_has_device(struct xrdp_smartcard *sc);

/**
 * Get the extracted certificate
 *
 * @param sc Smartcard context
 * @param[out] cert_der Pointer to DER-encoded certificate data
 * @param[out] cert_len Length of certificate data
 * @return 0 on success, 1 if no certificate available
 */
int
xrdp_smartcard_get_cert(struct xrdp_smartcard *sc,
                        const unsigned char **cert_der,
                        int *cert_len);

/**
 * Get the current state of the smartcard state machine
 *
 * @param sc Smartcard context
 * @return Current state
 */
enum xrdp_smartcard_state
xrdp_smartcard_get_state(struct xrdp_smartcard *sc);

/**
 * Generate the next RDPDR IOCTL request to send to the client
 *
 * This drives the smartcard state machine forward. After calling
 * xrdp_smartcard_process_rdpdr() to process a response, call this
 * to get the next request to send.
 *
 * @param sc Smartcard context
 * @param s Stream to write the next request into
 * @return 0 on success, 1 if no more requests needed, -1 on error
 */
int
xrdp_smartcard_build_next_request(struct xrdp_smartcard *sc,
                                  struct stream *s);

#endif /* XRDP_SMARTCARD_H */
