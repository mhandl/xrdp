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
 *
 * This module implements a simplified MS-RDPESC (smartcard) protocol
 * handler that runs in the xrdp daemon during the pre-authentication
 * phase. It drives a PIV APDU sequence to extract the X.509
 * certificate from a redirected virtual smartcard, without requiring
 * chansrv (which only starts after authentication).
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "xrdp_smartcard.h"
#include "os_calls.h"
#include "string_calls.h"
#include "log.h"

/* PIV Application AID: A0 00 00 03 08 00 00 10 00 01 00 */
static const unsigned char g_piv_aid[] =
{
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10,
    0x00, 0x01, 0x00
};

/* PIV Authentication Certificate Object ID: 5F C1 05 */
static const unsigned char g_piv_cert_oid[] =
{
    0x5F, 0xC1, 0x05
};

/* Maximum certificate size we'll accept (64 KB) */
#define MAX_CERT_SIZE (64 * 1024)

/* Maximum READ BINARY chunk size */
#define READ_BINARY_CHUNK 256

struct xrdp_smartcard
{
    enum xrdp_smartcard_state state;
    int has_smartcard_device;

    /* MS-RDPESC context and card handles */
    unsigned char context[16];
    int context_bytes;
    unsigned char card_handle[16];
    int card_handle_bytes;
    char reader_name[256];

    /* Certificate accumulation buffer */
    unsigned char *cert_der;
    int cert_len;
    int cert_alloc;
    int cert_offset; /* current read offset for READ BINARY */
    int cert_total;  /* total expected size from SELECT response */

    /* Completion ID tracking for RDPDR */
    unsigned int completion_id;
};

/*****************************************************************************/
struct xrdp_smartcard *
xrdp_smartcard_create(void)
{
    struct xrdp_smartcard *sc;

    sc = (struct xrdp_smartcard *) g_malloc(sizeof(*sc), 1);
    if (sc == 0)
    {
        return 0;
    }
    sc->state = XRDP_SC_IDLE;
    sc->completion_id = 1;
    return sc;
}

/*****************************************************************************/
void
xrdp_smartcard_delete(struct xrdp_smartcard *sc)
{
    if (sc == 0)
    {
        return;
    }
    g_free(sc->cert_der);
    g_free(sc);
}

/*****************************************************************************/
int
xrdp_smartcard_has_device(struct xrdp_smartcard *sc)
{
    if (sc == 0)
    {
        return 0;
    }
    return sc->has_smartcard_device;
}

/*****************************************************************************/
int
xrdp_smartcard_get_cert(struct xrdp_smartcard *sc,
                        const unsigned char **cert_der,
                        int *cert_len)
{
    if (sc == 0 || sc->state != XRDP_SC_DONE)
    {
        return 1;
    }
    if (sc->cert_der == 0 || sc->cert_len <= 0)
    {
        return 1;
    }
    *cert_der = sc->cert_der;
    *cert_len = sc->cert_len;
    return 0;
}

/*****************************************************************************/
enum xrdp_smartcard_state
xrdp_smartcard_get_state(struct xrdp_smartcard *sc)
{
    if (sc == 0)
    {
        return XRDP_SC_ERROR;
    }
    return sc->state;
}

/*****************************************************************************/
/**
 * Build a SELECT APDU command
 *
 * @param s Stream to write to
 * @param aid Application ID bytes
 * @param aid_len Length of AID
 */
static void
build_apdu_select(struct stream *s, const unsigned char *aid, int aid_len)
{
    /* CLA=00, INS=A4 (SELECT), P1=04 (by name), P2=00, Lc */
    out_uint8(s, 0x00);         /* CLA */
    out_uint8(s, 0xA4);         /* INS: SELECT */
    out_uint8(s, 0x04);         /* P1: Select by DF name */
    out_uint8(s, 0x00);         /* P2 */
    out_uint8(s, aid_len);      /* Lc */
    out_uint8a(s, aid, aid_len);
}

/*****************************************************************************/
/**
 * Build a SELECT DATA OBJECT APDU (for PIV cert retrieval)
 *
 * SELECT data object using GET DATA command with the BER-TLV tag
 * for the PIV certificate container.
 *
 * @param s Stream to write to
 * @param oid Object ID bytes
 * @param oid_len Length of OID
 */
static void
build_apdu_get_data(struct stream *s,
                    const unsigned char *oid, int oid_len)
{
    int data_len;

    /* GET DATA APDU: CLA=00 INS=CB P1=3F P2=FF Lc=TLV Le=00 */
    data_len = 2 + oid_len; /* tag(5C) + len + oid */
    out_uint8(s, 0x00);          /* CLA */
    out_uint8(s, 0xCB);          /* INS: GET DATA */
    out_uint8(s, 0x3F);          /* P1 */
    out_uint8(s, 0xFF);          /* P2 */
    out_uint8(s, data_len);      /* Lc */
    out_uint8(s, 0x5C);          /* Tag: tag list */
    out_uint8(s, oid_len);       /* Length of OID */
    out_uint8a(s, oid, oid_len); /* OID */
    out_uint8(s, 0x00);          /* Le: request all available bytes */
}

/*****************************************************************************/
/**
 * Build a READ BINARY APDU
 *
 * @param s Stream to write to
 * @param offset Byte offset to read from
 * @param length Number of bytes to read
 */
static void
build_apdu_read_binary(struct stream *s, int offset, int length)
{
    out_uint8(s, 0x00);              /* CLA */
    out_uint8(s, 0xB0);              /* INS: READ BINARY */
    out_uint8(s, (offset >> 8) & 0xFF); /* P1: offset high byte */
    out_uint8(s, offset & 0xFF);     /* P2: offset low byte */
    out_uint8(s, length & 0xFF);     /* Le: number of bytes */
}

/*****************************************************************************/
/**
 * Parse a BER-TLV length from a certificate response.
 * Returns the data length and advances *pos past the length field.
 *
 * @param data Buffer containing TLV data
 * @param data_len Total buffer length
 * @param[in,out] pos Current position, advanced past length
 * @return Length value, or -1 on error
 */
static int
parse_ber_length(const unsigned char *data, int data_len, int *pos)
{
    int p;
    int len;

    p = *pos;
    if (p >= data_len)
    {
        return -1;
    }
    if (data[p] < 0x80)
    {
        len = data[p];
        *pos = p + 1;
        return len;
    }
    if (data[p] == 0x81)
    {
        if (p + 1 >= data_len)
        {
            return -1;
        }
        len = data[p + 1];
        *pos = p + 2;
        return len;
    }
    if (data[p] == 0x82)
    {
        if (p + 2 >= data_len)
        {
            return -1;
        }
        len = (data[p + 1] << 8) | data[p + 2];
        *pos = p + 3;
        return len;
    }
    if (data[p] == 0x83)
    {
        if (p + 3 >= data_len)
        {
            return -1;
        }
        len = (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3];
        *pos = p + 4;
        return len;
    }
    return -1;
}

/*****************************************************************************/
/**
 * Parse the PIV certificate data from a GET DATA response.
 *
 * The response is BER-TLV encoded:
 *   53 (Discretionary data) -> contains:
 *     70 (Certificate) -> the DER certificate
 *     71 (CertInfo)
 *     FE (Error detection code)
 *
 * @param sc Smartcard context
 * @param data Response data (after status bytes)
 * @param data_len Response data length
 * @return 0 on success, 1 on error
 */
static int
parse_piv_cert_response(struct xrdp_smartcard *sc,
                        const unsigned char *data, int data_len)
{
    int pos;
    int outer_len;
    int tag;
    int inner_len;

    pos = 0;

    /* Outer tag should be 0x53 (Discretionary data) */
    if (pos >= data_len || data[pos] != 0x53)
    {
        LOG(LOG_LEVEL_ERROR,
            "parse_piv_cert_response: expected tag 0x53, got 0x%02x",
            pos < data_len ? data[pos] : 0);
        return 1;
    }
    pos++;
    outer_len = parse_ber_length(data, data_len, &pos);
    if (outer_len < 0)
    {
        LOG(LOG_LEVEL_ERROR,
            "parse_piv_cert_response: failed to parse outer length");
        return 1;
    }

    /* Look for tag 0x70 (Certificate) within the outer TLV */
    while (pos < data_len)
    {
        tag = data[pos];
        pos++;
        inner_len = parse_ber_length(data, data_len, &pos);
        if (inner_len < 0)
        {
            LOG(LOG_LEVEL_ERROR,
                "parse_piv_cert_response: failed to parse inner length");
            return 1;
        }
        if (tag == 0x70)
        {
            /* This is the certificate */
            if (inner_len > MAX_CERT_SIZE)
            {
                LOG(LOG_LEVEL_ERROR,
                    "parse_piv_cert_response: cert too large %d",
                    inner_len);
                return 1;
            }
            sc->cert_der = (unsigned char *) g_malloc(inner_len, 0);
            if (sc->cert_der == 0)
            {
                LOG(LOG_LEVEL_ERROR,
                    "parse_piv_cert_response: memory allocation failed");
                return 1;
            }
            if (pos + inner_len > data_len)
            {
                LOG(LOG_LEVEL_ERROR,
                    "parse_piv_cert_response: cert data truncated");
                g_free(sc->cert_der);
                sc->cert_der = 0;
                return 1;
            }
            g_memcpy(sc->cert_der, data + pos, inner_len);
            sc->cert_len = inner_len;
            LOG(LOG_LEVEL_INFO,
                "parse_piv_cert_response: extracted %d byte certificate",
                inner_len);
            return 0;
        }
        pos += inner_len;
    }

    LOG(LOG_LEVEL_ERROR,
        "parse_piv_cert_response: certificate tag 0x70 not found");
    return 1;
}

/*****************************************************************************/
/**
 * Process an APDU response, checking the SW1/SW2 status bytes.
 *
 * @param data Response data
 * @param data_len Response data length
 * @param[out] sw1 First status byte
 * @param[out] sw2 Second status byte
 * @return 0 if SW1/SW2 indicate success (90 00), 1 otherwise
 */
static int
check_apdu_status(const char *data, int data_len,
                  int *sw1, int *sw2)
{
    const unsigned char *udata;

    if (data_len < 2)
    {
        return 1;
    }
    udata = (const unsigned char *) data;
    *sw1 = udata[data_len - 2];
    *sw2 = udata[data_len - 1];

    if (*sw1 == 0x90 && *sw2 == 0x00)
    {
        return 0; /* success */
    }
    if (*sw1 == 0x61)
    {
        return 0; /* more data available, success */
    }
    return 1;
}

/*****************************************************************************/
int
xrdp_smartcard_process_rdpdr(struct xrdp_smartcard *sc,
                             struct stream *s)
{
    /* This is a simplified handler that processes MS-RDPESC IOCTL
     * responses. In the real implementation, this would be called
     * from the RDPDR channel handler in xrdp_mm.c when the
     * connection is in the pre-auth state.
     *
     * The full implementation would parse the RDPDR Device IO
     * Response header and extract the IOCTL output buffer, then
     * dispatch based on the current state. */

    if (sc == 0)
    {
        return -1;
    }

    LOG_DEVEL(LOG_LEVEL_DEBUG,
              "xrdp_smartcard_process_rdpdr: state=%d",
              sc->state);

    switch (sc->state)
    {
        case XRDP_SC_WAIT_ESTABLISH_CONTEXT:
        {
            /* Parse EstablishContext response - extract context */
            int status;

            if (!s_check_rem_and_log(s, 8,
                                     "xrdp_sc: establish context"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint32_le(s, status);
            if (status != 0)
            {
                LOG(LOG_LEVEL_ERROR,
                    "xrdp_sc: EstablishContext failed: 0x%08x",
                    status);
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            if (!s_check_rem_and_log(s, 4,
                                     "xrdp_sc: context bytes"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint32_le(s, sc->context_bytes);
            if (sc->context_bytes < 0 ||
                sc->context_bytes > (int) sizeof(sc->context))
            {
                LOG(LOG_LEVEL_ERROR,
                    "xrdp_sc: bad context_bytes %d",
                    sc->context_bytes);
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            if (!s_check_rem_and_log(s, sc->context_bytes,
                                     "xrdp_sc: context data"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint8a(s, sc->context, sc->context_bytes);
            sc->state = XRDP_SC_WAIT_LIST_READERS;
            return 0;
        }

        case XRDP_SC_WAIT_LIST_READERS:
        {
            /* Parse ListReaders response - get first reader name */
            int status;
            int num_readers;

            if (!s_check_rem_and_log(s, 8,
                                     "xrdp_sc: list readers"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint32_le(s, status);
            in_uint32_le(s, num_readers);
            if (status != 0 || num_readers <= 0)
            {
                LOG(LOG_LEVEL_ERROR,
                    "xrdp_sc: ListReaders failed: "
                    "status=0x%08x readers=%d",
                    status, num_readers);
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            /* Read first reader name (100 byte fixed field) */
            if (!s_check_rem_and_log(s, 100,
                                     "xrdp_sc: reader name"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint8a(s, sc->reader_name, 100);
            sc->reader_name[99] = '\0';
            LOG(LOG_LEVEL_INFO,
                "xrdp_sc: using reader: %s", sc->reader_name);
            sc->state = XRDP_SC_WAIT_CONNECT;
            return 0;
        }

        case XRDP_SC_WAIT_CONNECT:
        {
            /* Parse Connect response - get card handle */
            int status;

            if (!s_check_rem_and_log(s, 4,
                                     "xrdp_sc: connect status"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint32_le(s, status);
            if (status != 0)
            {
                LOG(LOG_LEVEL_ERROR,
                    "xrdp_sc: Connect failed: 0x%08x", status);
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            if (!s_check_rem_and_log(s, 4,
                                     "xrdp_sc: card handle bytes"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint32_le(s, sc->card_handle_bytes);
            if (sc->card_handle_bytes < 0 ||
                sc->card_handle_bytes > (int) sizeof(sc->card_handle))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            if (!s_check_rem_and_log(s, sc->card_handle_bytes,
                                     "xrdp_sc: card handle"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint8a(s, sc->card_handle, sc->card_handle_bytes);
            sc->state = XRDP_SC_WAIT_TRANSMIT_SELECT_PIV;
            return 0;
        }

        case XRDP_SC_WAIT_TRANSMIT_SELECT_PIV:
        {
            /* Parse Transmit response for SELECT PIV AID */
            int recv_len;
            char *recv_data;
            int sw1;
            int sw2;

            if (!s_check_rem_and_log(s, 4,
                                     "xrdp_sc: transmit recv_len"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint32_le(s, recv_len);
            if (recv_len < 2 || recv_len > 65536)
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            if (!s_check_rem_and_log(s, recv_len,
                                     "xrdp_sc: transmit data"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint8p(s, recv_data, recv_len);

            if (check_apdu_status(recv_data, recv_len, &sw1, &sw2) != 0)
            {
                LOG(LOG_LEVEL_ERROR,
                    "xrdp_sc: SELECT PIV failed: SW=%02x%02x",
                    sw1, sw2);
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            LOG(LOG_LEVEL_INFO,
                "xrdp_sc: PIV application selected successfully");
            sc->state = XRDP_SC_WAIT_TRANSMIT_SELECT_CERT;
            return 0;
        }

        case XRDP_SC_WAIT_TRANSMIT_SELECT_CERT:
        {
            /* Parse response for GET DATA (certificate object) */
            int recv_len;
            char *recv_data;
            int sw1;
            int sw2;

            if (!s_check_rem_and_log(s, 4,
                                     "xrdp_sc: get data recv_len"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint32_le(s, recv_len);
            if (recv_len < 2 || recv_len > MAX_CERT_SIZE + 256)
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            if (!s_check_rem_and_log(s, recv_len,
                                     "xrdp_sc: get data"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint8p(s, recv_data, recv_len);

            if (check_apdu_status(recv_data, recv_len,
                                  &sw1, &sw2) != 0)
            {
                LOG(LOG_LEVEL_ERROR,
                    "xrdp_sc: GET DATA failed: SW=%02x%02x",
                    sw1, sw2);
                sc->state = XRDP_SC_ERROR;
                return -1;
            }

            /* Parse the PIV certificate TLV from the response
             * (excluding the 2-byte status) */
            if (parse_piv_cert_response(
                    sc, (const unsigned char *) recv_data,
                    recv_len - 2) != 0)
            {
                LOG(LOG_LEVEL_ERROR,
                    "xrdp_sc: failed to parse certificate");
                sc->state = XRDP_SC_ERROR;
                return -1;
            }

            LOG(LOG_LEVEL_INFO,
                "xrdp_sc: certificate extracted, %d bytes",
                sc->cert_len);
            sc->state = XRDP_SC_WAIT_DISCONNECT;
            return 0;
        }

        case XRDP_SC_WAIT_TRANSMIT_READ_BINARY:
        {
            /* Parse READ BINARY response and accumulate cert data */
            int recv_len;
            char *recv_data;
            int sw1;
            int sw2;

            if (!s_check_rem_and_log(s, 4,
                                     "xrdp_sc: read binary len"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint32_le(s, recv_len);
            if (recv_len < 2 || recv_len > MAX_CERT_SIZE)
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            if (!s_check_rem_and_log(s, recv_len,
                                     "xrdp_sc: read binary data"))
            {
                sc->state = XRDP_SC_ERROR;
                return -1;
            }
            in_uint8p(s, recv_data, recv_len);

            if (check_apdu_status(recv_data, recv_len,
                                  &sw1, &sw2) != 0)
            {
                LOG(LOG_LEVEL_ERROR,
                    "xrdp_sc: READ BINARY failed: SW=%02x%02x",
                    sw1, sw2);
                sc->state = XRDP_SC_ERROR;
                return -1;
            }

            /* Append received data (minus status bytes) to cert */
            {
                int data_bytes = recv_len - 2;
                int new_len = sc->cert_offset + data_bytes;

                if (new_len > sc->cert_alloc)
                {
                    int new_alloc;
                    unsigned char *new_buf;

                    new_alloc = new_len + READ_BINARY_CHUNK;
                    if (new_alloc > MAX_CERT_SIZE)
                    {
                        new_alloc = MAX_CERT_SIZE;
                    }
                    new_buf = (unsigned char *)
                              g_malloc(new_alloc, 0);
                    if (new_buf == 0)
                    {
                        sc->state = XRDP_SC_ERROR;
                        return -1;
                    }
                    if (sc->cert_der != 0)
                    {
                        g_memcpy(new_buf, sc->cert_der,
                                 sc->cert_offset);
                        g_free(sc->cert_der);
                    }
                    sc->cert_der = new_buf;
                    sc->cert_alloc = new_alloc;
                }
                g_memcpy(sc->cert_der + sc->cert_offset,
                         recv_data, data_bytes);
                sc->cert_offset += data_bytes;
                sc->cert_len = sc->cert_offset;
            }

            /* Check if we've read everything */
            if (sw1 == 0x90 && sw2 == 0x00)
            {
                /* No more data */
                LOG(LOG_LEVEL_INFO,
                    "xrdp_sc: certificate read complete, %d bytes",
                    sc->cert_len);
                sc->state = XRDP_SC_WAIT_DISCONNECT;
            }
            /* sw1 == 0x61 means more data available */
            return 0;
        }

        case XRDP_SC_WAIT_DISCONNECT:
        {
            /* Disconnect response */
            sc->state = XRDP_SC_WAIT_RELEASE_CONTEXT;
            return 0;
        }

        case XRDP_SC_WAIT_RELEASE_CONTEXT:
        {
            /* ReleaseContext response - we're done */
            sc->state = XRDP_SC_DONE;
            return 1; /* cert extraction complete */
        }

        default:
            LOG(LOG_LEVEL_ERROR,
                "xrdp_sc: unexpected state %d", sc->state);
            sc->state = XRDP_SC_ERROR;
            return -1;
    }
}

/*****************************************************************************/
int
xrdp_smartcard_build_next_request(struct xrdp_smartcard *sc,
                                  struct stream *s)
{
    if (sc == 0)
    {
        return -1;
    }

    switch (sc->state)
    {
        case XRDP_SC_WAIT_ESTABLISH_CONTEXT:
            /* Build EstablishContext request */
            out_uint32_le(s, 0); /* dwScope = SCARD_SCOPE_SYSTEM */
            s_mark_end(s);
            return 0;

        case XRDP_SC_WAIT_LIST_READERS:
            /* Build ListReaders request */
            out_uint8a(s, sc->context, sc->context_bytes);
            out_uint32_le(s, 0); /* groups length */
            out_uint32_le(s, 0xFFFFFFFF); /* auto-allocate */
            s_mark_end(s);
            return 0;

        case XRDP_SC_WAIT_CONNECT:
        {
            int name_len;
            /* Build Connect request */
            out_uint8a(s, sc->context, sc->context_bytes);
            name_len = g_strlen(sc->reader_name);
            if (name_len > 99)
            {
                name_len = 99;
            }
            out_uint8a(s, sc->reader_name, name_len);
            out_uint8s(s, 100 - name_len);
            out_uint32_le(s, 0x02); /* SCARD_SHARE_SHARED */
            out_uint32_le(s, 0x03); /* T0 | T1 */
            s_mark_end(s);
            return 0;
        }

        case XRDP_SC_WAIT_TRANSMIT_SELECT_PIV:
            /* Build Transmit: SELECT PIV AID */
            out_uint8a(s, sc->card_handle, sc->card_handle_bytes);
            out_uint32_le(s, 0x01); /* T0 protocol */
            out_uint32_le(s, 8);    /* cbPciLength */
            out_uint32_le(s, 0);    /* extra_len */
            {
                int apdu_start;
                int apdu_len;

                apdu_start = (int)(s->p - s->data);
                out_uint32_le(s, 0); /* placeholder for send_bytes */
                build_apdu_select(s, g_piv_aid,
                                  (int) sizeof(g_piv_aid));
                apdu_len = (int)(s->p - s->data) - apdu_start - 4;
                /* patch send_bytes */
                {
                    char *save_p = s->p;
                    s->p = s->data + apdu_start;
                    out_uint32_le(s, apdu_len);
                    s->p = save_p;
                }
            }
            /* recv pci: none */
            out_uint32_le(s, 0);
            out_uint32_le(s, 0);
            out_uint32_le(s, 0);
            /* recv buffer length */
            out_uint32_le(s, 258);
            s_mark_end(s);
            return 0;

        case XRDP_SC_WAIT_TRANSMIT_SELECT_CERT:
            /* Build Transmit: GET DATA for PIV cert */
            out_uint8a(s, sc->card_handle, sc->card_handle_bytes);
            out_uint32_le(s, 0x01); /* T0 protocol */
            out_uint32_le(s, 8);    /* cbPciLength */
            out_uint32_le(s, 0);    /* extra_len */
            {
                int apdu_start;
                int apdu_len;

                apdu_start = (int)(s->p - s->data);
                out_uint32_le(s, 0); /* placeholder */
                build_apdu_get_data(s, g_piv_cert_oid,
                                    (int) sizeof(g_piv_cert_oid));
                apdu_len = (int)(s->p - s->data) - apdu_start - 4;
                {
                    char *save_p = s->p;
                    s->p = s->data + apdu_start;
                    out_uint32_le(s, apdu_len);
                    s->p = save_p;
                }
            }
            out_uint32_le(s, 0);
            out_uint32_le(s, 0);
            out_uint32_le(s, 0);
            out_uint32_le(s, MAX_CERT_SIZE);
            s_mark_end(s);
            return 0;

        case XRDP_SC_WAIT_TRANSMIT_READ_BINARY:
            /* Build Transmit: READ BINARY */
            out_uint8a(s, sc->card_handle, sc->card_handle_bytes);
            out_uint32_le(s, 0x01);
            out_uint32_le(s, 8);
            out_uint32_le(s, 0);
            {
                int apdu_start;
                int apdu_len;

                apdu_start = (int)(s->p - s->data);
                out_uint32_le(s, 0); /* placeholder */
                build_apdu_read_binary(s, sc->cert_offset,
                                       READ_BINARY_CHUNK);
                apdu_len = (int)(s->p - s->data) - apdu_start - 4;
                {
                    char *save_p = s->p;
                    s->p = s->data + apdu_start;
                    out_uint32_le(s, apdu_len);
                    s->p = save_p;
                }
            }
            out_uint32_le(s, 0);
            out_uint32_le(s, 0);
            out_uint32_le(s, 0);
            out_uint32_le(s, READ_BINARY_CHUNK + 2);
            s_mark_end(s);
            return 0;

        case XRDP_SC_WAIT_DISCONNECT:
            /* Build Disconnect request */
            out_uint8a(s, sc->card_handle, sc->card_handle_bytes);
            out_uint32_le(s, 0x00); /* SCARD_LEAVE_CARD */
            s_mark_end(s);
            return 0;

        case XRDP_SC_WAIT_RELEASE_CONTEXT:
            /* Build ReleaseContext request */
            out_uint8a(s, sc->context, sc->context_bytes);
            s_mark_end(s);
            return 0;

        case XRDP_SC_DONE:
        case XRDP_SC_ERROR:
            return 1; /* no more requests */

        default:
            return -1;
    }
}
