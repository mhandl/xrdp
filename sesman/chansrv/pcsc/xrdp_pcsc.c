#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <poll.h>

#include "os_calls.h"
#include "string_calls.h"
#include "xrdp_constants.h"

#define PCSC_API

typedef unsigned char BYTE;
typedef BYTE *LPBYTE;
#ifdef __APPLE__
typedef int LONG;
typedef unsigned int DWORD;
#else
typedef long LONG;
typedef unsigned long DWORD;
#endif
typedef DWORD *LPDWORD;
typedef const void *LPCVOID;
typedef const char *LPCSTR;
typedef char *LPSTR;
typedef void *LPVOID;
typedef const BYTE *LPCBYTE;

typedef LONG SCARDCONTEXT;
typedef SCARDCONTEXT *LPSCARDCONTEXT;

typedef LONG SCARDHANDLE;
typedef SCARDHANDLE *LPSCARDHANDLE;

#define MAX_ATR_SIZE 33

typedef struct _SCARD_READERSTATE
{
    const char *szReader;
    void *pvUserData;
    DWORD dwCurrentState;
    DWORD dwEventState;
    DWORD cbAtr;
    unsigned char rgbAtr[MAX_ATR_SIZE];
} SCARD_READERSTATE, *LPSCARD_READERSTATE;

typedef struct _SCARD_IO_REQUEST
{
    unsigned long dwProtocol;
    unsigned long cbPciLength;
} SCARD_IO_REQUEST, *PSCARD_IO_REQUEST, *LPSCARD_IO_REQUEST;

#define SCARD_PROTOCOL_T0       0x0001 /**< T=0 active protocol. */
#define SCARD_PROTOCOL_T1       0x0002 /**< T=1 active protocol. */
#define SCARD_PROTOCOL_RAW      0x0004 /**< Raw active protocol. */

PCSC_API SCARD_IO_REQUEST g_rgSCardT0Pci  = { SCARD_PROTOCOL_T0,  8 };
PCSC_API SCARD_IO_REQUEST g_rgSCardT1Pci  = { SCARD_PROTOCOL_T1,  8 };
PCSC_API SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, 8 };

#define LLOG_LEVEL 5
#define LLOGLN(_level, _args) \
    do { if (_level < LLOG_LEVEL) { printf _args ; printf("\n"); } } while (0)
#define LHEXDUMP(_level, _args) \
    do { if  (_level < LLOG_LEVEL) { lhexdump _args ; } } while (0)

#define SCARD_ESTABLISH_CONTEXT  0x01
#define SCARD_RELEASE_CONTEXT    0x02
#define SCARD_LIST_READERS       0x03
#define SCARD_CONNECT            0x04
#define SCARD_RECONNECT          0x05
#define SCARD_DISCONNECT         0x06
#define SCARD_BEGIN_TRANSACTION  0x07
#define SCARD_END_TRANSACTION    0x08
#define SCARD_TRANSMIT           0x09
#define SCARD_CONTROL            0x0A
#define SCARD_STATUS             0x0B
#define SCARD_GET_STATUS_CHANGE  0x0C
#define SCARD_CANCEL             0x0D
#define SCARD_CANCEL_TRANSACTION 0x0E
#define SCARD_GET_ATTRIB         0x0F
#define SCARD_SET_ATTRIB         0x10

#define SCARD_S_SUCCESS 0x00000000
#define SCARD_F_INTERNAL_ERROR ((LONG)0x80100001)

#define SET_UINT32(_data, _offset, _val) do { \
        (((BYTE*)(_data)) + (_offset))[0] = ((_val) >> 0)  & 0xff; \
        (((BYTE*)(_data)) + (_offset))[1] = ((_val) >> 8)  & 0xff; \
        (((BYTE*)(_data)) + (_offset))[2] = ((_val) >> 16) & 0xff; \
        (((BYTE*)(_data)) + (_offset))[3] = ((_val) >> 24) & 0xff; } while (0)

#define GET_UINT32(_data, _offset) \
    ((((BYTE*)(_data)) + (_offset))[0] << 0)  | \
    ((((BYTE*)(_data)) + (_offset))[1] << 8)  | \
    ((((BYTE*)(_data)) + (_offset))[2] << 16) | \
    ((((BYTE*)(_data)) + (_offset))[3] << 24)

#define LMIN(_val1, _val2) (_val1) < (_val2) ? (_val1) : (_val2)
#define LMAX(_val1, _val2) (_val1) > (_val2) ? (_val1) : (_val2)

#define PCSC_MAX_MSG_SIZE (1024 * 1024)  /* 1 MB cap for message buffers */

/*****************************************************************************/
/* Allocate a message buffer with overflow checking.
 * Returns NULL if the requested size is invalid or exceeds the cap. */
static char *
alloc_msg_buf(int size)
{
    if (size <= 0 || size > PCSC_MAX_MSG_SIZE)
    {
        LLOGLN(0, ("alloc_msg_buf: invalid size %d", size));
        return NULL;
    }
    return (char *) g_malloc_nofail(size);
}

static int g_sck = -1; /* unix domain socket */

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* for pcsc_stringify_error — thread-local to avoid races */
static __thread char g_error_str[512];

/*****************************************************************************/
/* produce a hex dump */
static void
lhexdump(void *p, int len)
{
    unsigned char *line;
    int i;
    int thisline;
    int offset;

    line = (unsigned char *)p;
    offset = 0;

    while (offset < len)
    {
        printf("%04x ", offset);
        thisline = len - offset;

        if (thisline > 16)
        {
            thisline = 16;
        }

        for (i = 0; i < thisline; i++)
        {
            printf("%02x ", line[i]);
        }

        for (; i < 16; i++)
        {
            printf("   ");
        }

        for (i = 0; i < thisline; i++)
        {
            printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');
        }

        printf("\n");
        offset += thisline;
        line += thisline;
    }
}

/*****************************************************************************/
static int
connect_to_chansrv(void)
{
    int bytes;
    char disstr[MAX_DISPLAY_NAME_SIZE];
    int error;
    char *xrdp_session;
    char *home_str;
    struct sockaddr_un saddr;
    struct sockaddr *psaddr;

    pthread_mutex_lock(&g_mutex);
    if (g_sck != -1)
    {
        /* already connected */
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }
    xrdp_session = getenv("XRDP_SESSION");
    if (xrdp_session == NULL)
    {
        /* XRDP_SESSION must be set */
        LLOGLN(0, ("connect_to_chansrv: error, not xrdp session"));
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }

    if (g_get_display_string(disstr, sizeof(disstr)) < 0)
    {
        LLOGLN(0, ("connect_to_chansrv: error, don't understand DISPLAY"));
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    home_str = getenv("HOME");
    if (home_str == NULL)
    {
        /* HOME must be set */
        LLOGLN(0, ("connect_to_chansrv: error, home not set"));
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    g_sck = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (g_sck == -1)
    {
        LLOGLN(0, ("connect_to_chansrv: error, socket failed"));
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    memset(&saddr, 0, sizeof(struct sockaddr_un));
    saddr.sun_family = AF_UNIX;
    bytes = sizeof(saddr.sun_path);
    snprintf(saddr.sun_path, bytes, "%s/.pcsc%s/pcscd.comm", home_str, disstr);
    saddr.sun_path[bytes - 1] = 0;
    LLOGLN(10, ("connect_to_chansrv: connecting to %s", saddr.sun_path));
    psaddr = (struct sockaddr *) &saddr;
    bytes = sizeof(struct sockaddr_un);
    error = connect(g_sck, psaddr, bytes);
    if (error == 0)
    {
    }
    else
    {
        perror("connect_to_chansrv");
        close(g_sck);
        g_sck = -1;
        LLOGLN(0, ("connect_to_chansrv: error, open %s", saddr.sun_path));
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

/*****************************************************************************/
static int
send_message(int code, char *data, int bytes)
{
    char header[8];

    pthread_mutex_lock(&g_mutex);
    SET_UINT32(header, 0, bytes);
    SET_UINT32(header, 4, code);
    if (send(g_sck, header, 8, 0) != 8)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    if (send(g_sck, data, bytes, 0) != bytes)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    LLOGLN(10, ("send_message:"));
    LHEXDUMP(10, (data, bytes));
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

/*****************************************************************************/
static int
get_message(int *code, char *data, int *bytes)
{
    char header[8];
    int max_bytes;
    int error;
    int recv_rv;
    int lcode;
    struct pollfd pollfd;

    LLOGLN(10, ("get_message:"));
    while (1)
    {
        LLOGLN(10, ("get_message: loop"));
        pollfd.fd = g_sck;
        pollfd.events = POLLIN;
        pollfd.revents = 0;
        error = poll(&pollfd, 1, 1000);
        if (error == 1)
        {
            pthread_mutex_lock(&g_mutex);
            pollfd.fd = g_sck;
            pollfd.events = POLLIN;
            pollfd.revents = 0;
            error = poll(&pollfd, 1, 0);
            if (error == 1)
            {
                /* just take a look at the next message */
                recv_rv = recv(g_sck, header, 8, MSG_PEEK);
                if (recv_rv == 8)
                {
                    lcode = GET_UINT32(header, 4);
                    if (lcode == *code)
                    {
                        /* still have mutex lock */
                        break;
                    }
                    else
                    {
                        LLOGLN(10, ("get_message: lcode %d *code %d",
                                    lcode, *code));
                    }
                }
                else if (recv_rv == 0)
                {
                    pthread_mutex_unlock(&g_mutex);
                    LLOGLN(0, ("get_message: recv_rv 0, disconnect"));
                    return 1;
                }
                else
                {
                    LLOGLN(10, ("get_message: recv_rv %d", recv_rv));
                }
            }
            else
            {
                LLOGLN(10, ("get_message: select return %d", error));
            }
            pthread_mutex_unlock(&g_mutex);
            usleep(1000);
        }
    }

    if (recv(g_sck, header, 8, 0) != 8)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    max_bytes = *bytes;
    *bytes = GET_UINT32(header, 0);
    *code = GET_UINT32(header, 4);
    if (*bytes > max_bytes)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    if (recv(g_sck, data, *bytes, 0) != *bytes)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

/*****************************************************************************/
PCSC_API LONG
SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2,
                      LPSCARDCONTEXT phContext)
{
    char msg[256];
    DWORD context;
    int code;
    int bytes;
    int status;

    LLOGLN(10, ("SCardEstablishContext:"));
    if (g_sck == -1)
    {
        if (connect_to_chansrv() != 0)
        {
            LLOGLN(0, ("SCardEstablishContext: error, can not connect "
                       "to chansrv"));
            return SCARD_F_INTERNAL_ERROR;
        }
    }
    SET_UINT32(msg, 0, dwScope);
    if (send_message(SCARD_ESTABLISH_CONTEXT, msg, 4) != 0)
    {
        LLOGLN(0, ("SCardEstablishContext: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_ESTABLISH_CONTEXT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardEstablishContext: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_ESTABLISH_CONTEXT) || (bytes != 8))
    {
        LLOGLN(0, ("SCardEstablishContext: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    context = GET_UINT32(msg, 0);
    status = GET_UINT32(msg, 4);
    LLOGLN(10, ("SCardEstablishContext: got context 0x%8.8x", (int)context));
    *phContext = context;
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardReleaseContext(SCARDCONTEXT hContext)
{
    char msg[256];
    int code;
    int bytes;
    int status;

    LLOGLN(10, ("SCardReleaseContext:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardReleaseContext: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hContext);
    if (send_message(SCARD_RELEASE_CONTEXT, msg, 4) != 0)
    {
        LLOGLN(0, ("SCardReleaseContext: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_RELEASE_CONTEXT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardReleaseContext: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_RELEASE_CONTEXT) || (bytes != 4))
    {
        LLOGLN(0, ("SCardReleaseContext: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    LLOGLN(10, ("SCardReleaseContext: got status 0x%8.8x", status));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardIsValidContext(SCARDCONTEXT hContext)
{
    LLOGLN(10, ("SCardIsValidContext:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardIsValidContext: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API LONG
SCardConnect(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
             DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
             LPDWORD pdwActiveProtocol)
{
    char msg[256];
    int code;
    int bytes;
    int status;
    int offset;

    LLOGLN(10, ("SCardConnect:"));
    LLOGLN(10, ("SCardConnect: hContext 0x%8.8x szReader %s dwShareMode %d "
                "dwPreferredProtocols %d",
                (int)hContext, szReader, (int)dwShareMode, (int)dwPreferredProtocols));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardConnect: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    SET_UINT32(msg, offset, hContext);
    offset += 4;
    bytes = strlen(szReader);
    if (bytes > 99)
    {
        LLOGLN(0, ("SCardConnect: error, name too long"));
        return SCARD_F_INTERNAL_ERROR;
    }
    memcpy(msg + offset, szReader, bytes);
    memset(msg + offset + bytes, 0, 100 - bytes);
    offset += 100;
    SET_UINT32(msg, offset, dwShareMode);
    offset += 4;
    SET_UINT32(msg, offset, dwPreferredProtocols);
    offset += 4;
    if (send_message(SCARD_CONNECT, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardConnect: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_CONNECT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardConnect: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_CONNECT)
    {
        LLOGLN(0, ("SCardConnect: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    *phCard = GET_UINT32(msg, 0);
    *pdwActiveProtocol = GET_UINT32(msg, 4);
    status = GET_UINT32(msg, 8);
    LLOGLN(10, ("SCardConnect: got status 0x%8.8x hCard 0x%8.8x "
                "dwActiveProtocol %d",
                status, (int)*phCard, (int)*pdwActiveProtocol));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode,
               DWORD dwPreferredProtocols, DWORD dwInitialization,
               LPDWORD pdwActiveProtocol)
{
    LLOGLN(0, ("SCardReconnect:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardReconnect: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API LONG
SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition)
{
    char msg[256];
    int code;
    int bytes;
    int status;

    LLOGLN(10, ("SCardDisconnect: hCard 0x%8.8x dwDisposition %d",
                (int)hCard, (int)dwDisposition));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardDisconnect: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hCard);
    SET_UINT32(msg, 4, dwDisposition);
    if (send_message(SCARD_DISCONNECT, msg, 8) != 0)
    {
        LLOGLN(0, ("SCardDisconnect: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_DISCONNECT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardDisconnect: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_DISCONNECT) || (bytes != 4))
    {
        LLOGLN(0, ("SCardDisconnect: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    LLOGLN(10, ("SCardDisconnect: got status 0x%8.8x", status));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardBeginTransaction(SCARDHANDLE hCard)
{
    char msg[256];
    int code;
    int bytes;
    int status;

    LLOGLN(10, ("SCardBeginTransaction: hCard 0x%8.8x", (int)hCard));
    if (hCard == 0)
    {
        LLOGLN(0, ("SCardBeginTransaction: error, bad hCard"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardBeginTransaction: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hCard);
    if (send_message(SCARD_BEGIN_TRANSACTION, msg, 4) != 0)
    {
        LLOGLN(0, ("SCardBeginTransaction: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_BEGIN_TRANSACTION;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardBeginTransaction: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_BEGIN_TRANSACTION) || (bytes != 4))
    {
        LLOGLN(0, ("SCardBeginTransaction: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    LLOGLN(10, ("SCardBeginTransaction: got status 0x%8.8x", status));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition)
{
    char msg[256];
    int code;
    int bytes;
    int status;

    LLOGLN(10, ("SCardEndTransaction:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardEndTransaction: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hCard);
    SET_UINT32(msg, 4, dwDisposition);
    if (send_message(SCARD_END_TRANSACTION, msg, 8) != 0)
    {
        LLOGLN(0, ("SCardEndTransaction: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_END_TRANSACTION;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardEndTransaction: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_END_TRANSACTION) || (bytes != 4))
    {
        LLOGLN(0, ("SCardEndTransaction: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    LLOGLN(10, ("SCardEndTransaction: got status 0x%8.8x", status));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardStatus(SCARDHANDLE hCard, LPSTR mszReaderName, LPDWORD pcchReaderLen,
            LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr,
            LPDWORD pcbAtrLen)
{
    char *msg;
    int code;
    int bytes;
    int status;
    int offset;
    int cchReaderLen;
    int orig_atr_len;
    int to_copy;

    LLOGLN(10, ("SCardStatus:"));
    if (hCard == 0)
    {
        LLOGLN(10, ("SCardStatus: error, bad hCard"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardStatus: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    LLOGLN(10, ("  hCard 0x%8.8x", (int)hCard));
    LLOGLN(10, ("  cchReaderLen %d", (int)*pcchReaderLen));
    LLOGLN(10, ("  cbAtrLen %d", (int)*pcbAtrLen));

    cchReaderLen = *pcchReaderLen;
    orig_atr_len = *pcbAtrLen;
    {
        /* Response: 4(readerLen) + readerLen + 4(state) + 4(proto) +
         * 4(atrLen) + atrLen + 4(status) = 20 + readerLen + atrLen */
        int msg_size = 20 + cchReaderLen + orig_atr_len;
        if (msg_size < 256)
        {
            msg_size = 256;
        }
        msg = alloc_msg_buf(msg_size);
        if (msg == NULL)
        {
            LLOGLN(0, ("SCardStatus: error, alloc_msg_buf"));
            return SCARD_F_INTERNAL_ERROR;
        }
    }
    SET_UINT32(msg, 0, hCard);
    SET_UINT32(msg, 4, cchReaderLen);
    SET_UINT32(msg, 8, *pcbAtrLen);
    if (send_message(SCARD_STATUS, msg, 12) != 0)
    {
        LLOGLN(0, ("SCardStatus: error, send_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    {
        int msg_size = 20 + cchReaderLen + orig_atr_len;
        if (msg_size < 256)
        {
            msg_size = 256;
        }
        bytes = msg_size;
    }
    code = SCARD_STATUS;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardStatus: error, get_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_STATUS)
    {
        LLOGLN(0, ("SCardStatus: error, bad code"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }

    LLOGLN(10, ("SCardStatus: cchReaderLen in %d", (int)*pcchReaderLen));
    offset = 0;
    *pcchReaderLen = GET_UINT32(msg, offset);
    LLOGLN(10, ("SCardStatus: cchReaderLen out %d", (int)*pcchReaderLen));
    offset += 4;
    /* Validate pcchReaderLen against remaining message bytes */
    if ((int)*pcchReaderLen < 0 ||
        (int)*pcchReaderLen > bytes - offset - 12)
    {
        LLOGLN(0, ("SCardStatus: error, pcchReaderLen %d exceeds "
                    "message bounds", (int)*pcchReaderLen));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (cchReaderLen > 0)
    {
        to_copy = cchReaderLen - 1;
        if ((int)*pcchReaderLen < to_copy)
        {
            to_copy = *pcchReaderLen;
        }
        memcpy(mszReaderName, msg + offset, to_copy);
        mszReaderName[to_copy] = 0;
    }
    LLOGLN(10, ("SCardStatus: mszReaderName out %s", mszReaderName));
    offset += *pcchReaderLen;
    *pdwState = GET_UINT32(msg, offset);
    if (*pdwState == 1)
    {
        *pdwState = 0x34;
    }
    LLOGLN(10, ("SCardStatus: dwState %d", (int)*pdwState));
    offset += 4;
    *pdwProtocol = GET_UINT32(msg, offset);
    LLOGLN(10, ("SCardStatus: dwProtocol %d", (int)*pdwProtocol));
    offset += 4;
    *pcbAtrLen = GET_UINT32(msg, offset);
    offset += 4;
    LLOGLN(10, ("SCardStatus: cbAtrLen %d", (int)*pcbAtrLen));
    /* Validate pcbAtrLen against caller's buffer */
    if ((int)*pcbAtrLen > orig_atr_len)
    {
        LLOGLN(0, ("SCardStatus: error, server returned atr_len %d "
                    "but buffer is only %d",
                    (int)*pcbAtrLen, orig_atr_len));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    memcpy(pbAtr, msg + offset, *pcbAtrLen);
    offset += *pcbAtrLen;
    status = GET_UINT32(msg, offset);
    LLOGLN(10, ("SCardStatus: status %d", status));
    offset += 4;
    free(msg);
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardGetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout,
                     LPSCARD_READERSTATE rgReaderStates, DWORD cReaders)
{
    char *msg;
    const char *rname;
    int bytes;
    int code;
    int index;
    int offset;
    int str_len;
    int status;
    int dwCurrentState;
    int dwEventState;
    int cbAtr;
    char atr[36];

    LLOGLN(10, ("SCardGetStatusChange:"));
    LLOGLN(10, ("  dwTimeout %d cReaders %d", (int)dwTimeout, (int)cReaders));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    /* Check for integer overflow: each reader needs 148 bytes */
    if (cReaders > (PCSC_MAX_MSG_SIZE - 12) / 148)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, cReaders %d too large",
                    (int)cReaders));
        return SCARD_F_INTERNAL_ERROR;
    }
    {
        int msg_size = 12 + (int)cReaders * 148;
        msg = alloc_msg_buf(msg_size);
        if (msg == NULL)
        {
            LLOGLN(0, ("SCardGetStatusChange: error, alloc_msg_buf"));
            return SCARD_F_INTERNAL_ERROR;
        }
    }
    SET_UINT32(msg, 0, hContext);
    SET_UINT32(msg, 4, dwTimeout);
    SET_UINT32(msg, 8, cReaders);
    offset = 12;
    for (index = 0; index < cReaders; index++)
    {
        rgReaderStates[index].dwCurrentState &= ~2;
        rgReaderStates[index].dwEventState &= ~2;
        rname = rgReaderStates[index].szReader;
        if (strcmp(rname, "\\\\?PnP?\\Notification") == 0)
        {
            LLOGLN(10, ("  \\\\?PnP?\\Notification present"));
            dwCurrentState = 0;
            dwEventState = 0;
            cbAtr = 0;
            memset(atr, 0, 36);
        }
        else
        {
            dwCurrentState = rgReaderStates[index].dwCurrentState;
            dwEventState = rgReaderStates[index].dwEventState;
            cbAtr = rgReaderStates[index].cbAtr;
            memset(atr, 0, 36);
            memcpy(atr, rgReaderStates[index].rgbAtr, 33);
        }
        str_len = strlen(rname);
        str_len = LMIN(str_len, 99);
        memset(msg + offset, 0, 100);
        memcpy(msg + offset, rname, str_len);
        LLOGLN(10, ("  in szReader       %s", rname));
        offset += 100;
        LLOGLN(10, ("  in dwCurrentState 0x%8.8x", dwCurrentState));
        SET_UINT32(msg, offset, dwCurrentState);
        offset += 4;
        LLOGLN(10, ("  in dwEventState   0x%8.8x", dwEventState));
        SET_UINT32(msg, offset, dwEventState);
        offset += 4;
        LLOGLN(10, ("  in cbAtr          %d", cbAtr));
        SET_UINT32(msg, offset, cbAtr);
        offset += 4;
        memcpy(msg + offset, atr, 36);
        offset += 36;
    }
    if (send_message(SCARD_GET_STATUS_CHANGE, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, send_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    /* Reuse msg buffer for response; ensure it's large enough.
     * Response: 4 + cReaders * 48 + 4 bytes */
    {
        int resp_size = 8 + (int)cReaders * 48;
        if (resp_size > 12 + (int)cReaders * 148)
        {
            free(msg);
            msg = alloc_msg_buf(resp_size);
            if (msg == NULL)
            {
                LLOGLN(0, ("SCardGetStatusChange: error, alloc resp"));
                return SCARD_F_INTERNAL_ERROR;
            }
        }
        bytes = resp_size > 12 + (int)cReaders * 148
                ? resp_size
                : 12 + (int)cReaders * 148;
    }
    code = SCARD_GET_STATUS_CHANGE;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, get_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_GET_STATUS_CHANGE)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, bad code"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    cReaders = GET_UINT32(msg, 0);
    offset = 4;
    LLOGLN(10, ("SCardGetStatusChange: got back cReaders %d", (int)cReaders));
    for (index = 0; index < cReaders; index++)
    {
        rname = rgReaderStates[index].szReader;
#if 1
        if (strcmp(rname, "\\\\?PnP?\\Notification") == 0)
        {
            LLOGLN(10, ("  out szReader       %s", rgReaderStates[index].szReader));
            dwCurrentState = GET_UINT32(msg, offset);
            rgReaderStates[index].dwCurrentState = dwCurrentState;
            offset += 4;
            LLOGLN(10, ("  out dwCurrentState 0x%8.8x", dwCurrentState));
            // disable PnP for now
            dwEventState = 4; // GET_UINT32(msg, offset);
            rgReaderStates[index].dwEventState = dwEventState;
            offset += 4;
            LLOGLN(10, ("  out dwEventState   0x%8.8x", dwEventState));
            cbAtr = GET_UINT32(msg, offset);
            rgReaderStates[index].cbAtr = cbAtr;
            offset += 4;
            LLOGLN(10, ("  out cbAtr          %d", cbAtr));
            memcpy(rgReaderStates[index].rgbAtr, msg + offset, 33);
            offset += 36;
        }
        else
#endif
        {
            LLOGLN(10, ("  out szReader       %s", rgReaderStates[index].szReader));
            dwCurrentState = GET_UINT32(msg, offset);
            rgReaderStates[index].dwCurrentState = dwCurrentState;
            offset += 4;
            LLOGLN(10, ("  out dwCurrentState 0x%8.8x", dwCurrentState));
            dwEventState = GET_UINT32(msg, offset);
            rgReaderStates[index].dwEventState = dwEventState;
            offset += 4;
            LLOGLN(10, ("  out dwEventState   0x%8.8x", dwEventState));
            cbAtr = GET_UINT32(msg, offset);
            rgReaderStates[index].cbAtr = cbAtr;
            offset += 4;
            LLOGLN(10, ("  out cbAtr          %d", cbAtr));
            memcpy(rgReaderStates[index].rgbAtr, msg + offset, 33);
            offset += 36;
        }
    }
    status = GET_UINT32(msg, offset);
    offset += 4;
    free(msg);
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardControl(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer,
             DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength,
             LPDWORD lpBytesReturned)
{
    char *msg;
    int bytes;
    int code;
    int offset;
    int status = 0;

    LLOGLN(10, ("SCardControl:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardControl: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    LLOGLN(10, ("  hCard 0x%8.8x", (int)hCard));
    LLOGLN(10, ("  dwControlCode 0x%8.8x", (int)dwControlCode));
    LLOGLN(10, ("  cbSendLength %d", (int)cbSendLength));
    LLOGLN(10, ("  cbRecvLength %d", (int)cbRecvLength));

    /* #define SCARD_CTL_CODE(code) (0x42000000 + (code))
       control_code = (control_code & 0x3ffc) >> 2;
       control_code = SCARD_CTL_CODE(control_code); */

    /* PCSC to Windows control code conversion.
     * PCSC: SCARD_CTL_CODE(code) = 0x42000000 + code
     * Windows: CTL_CODE(FILE_DEVICE_SMARTCARD=49, code, METHOD_BUFFERED=0,
     *          FILE_ANY_ACCESS=0) = (49 << 16) | (code << 2)
     * So: extract code = pcsc_ctl - 0x42000000, then apply Windows formula */
    dwControlCode = dwControlCode - 0x42000000;
    dwControlCode = dwControlCode << 2;
    dwControlCode = dwControlCode | (49 << 16);
    LLOGLN(10, ("  MS dwControlCode 0x%8.8d", (int)dwControlCode));

    {
        int msg_size = 16 + (int)cbSendLength + 4;
        int resp_size = 4 + (int)cbRecvLength + 4;
        if (resp_size > msg_size)
        {
            msg_size = resp_size;
        }
        msg = alloc_msg_buf(msg_size);
        if (msg == NULL)
        {
            LLOGLN(0, ("SCardControl: error, alloc_msg_buf"));
            return SCARD_F_INTERNAL_ERROR;
        }
    }
    offset = 0;
    SET_UINT32(msg, offset, hCard);
    offset += 4;
    SET_UINT32(msg, offset, dwControlCode);
    offset += 4;
    SET_UINT32(msg, offset, cbSendLength);
    offset += 4;
    memcpy(msg + offset, pbSendBuffer, cbSendLength);
    offset += cbSendLength;
    SET_UINT32(msg, offset, cbRecvLength);
    offset += 4;
    if (send_message(SCARD_CONTROL, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardControl: error, send_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    {
        int resp_size = 4 + (int)cbRecvLength + 4;
        int send_size = 16 + (int)cbSendLength + 4;
        bytes = resp_size > send_size ? resp_size : send_size;
    }
    code = SCARD_CONTROL;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardControl: error, get_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_CONTROL)
    {
        LLOGLN(0, ("SCardControl: error, bad code"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    *lpBytesReturned = GET_UINT32(msg, offset);
    LLOGLN(10, ("  cbRecvLength %d", (int)*lpBytesReturned));
    offset += 4;
    if (*lpBytesReturned > cbRecvLength)
    {
        LLOGLN(0, ("SCardControl: error, server returned %d bytes "
                    "but buffer is only %d",
                    (int)*lpBytesReturned, (int)cbRecvLength));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    memcpy(pbRecvBuffer, msg + offset, *lpBytesReturned);
    offset += *lpBytesReturned;
    status = GET_UINT32(msg, offset);
    free(msg);
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardTransmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci,
              LPCBYTE pbSendBuffer, DWORD cbSendLength,
              SCARD_IO_REQUEST *pioRecvPci, LPBYTE pbRecvBuffer,
              LPDWORD pcbRecvLength)
{
    char *msg;
    int bytes;
    int code;
    int offset;
    int status;
    int extra_len;
    int got_recv_pci;
    DWORD orig_recv_len;

    LLOGLN(10, ("SCardTransmit:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardTransmit: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }

    orig_recv_len = *pcbRecvLength;
    LLOGLN(10, ("  hCard 0x%8.8x", (int)hCard));
    LLOGLN(10, ("  cbSendLength %d", (int)cbSendLength));
    LLOGLN(10, ("  cbRecvLength %d", (int)*pcbRecvLength));
    LLOGLN(10, ("  pioSendPci->dwProtocol %d", (int)(pioSendPci->dwProtocol)));
    LLOGLN(10, ("  pioSendPci->cbPciLength %d", (int)(pioSendPci->cbPciLength)));
    LLOGLN(10, ("  pioRecvPci %p", pioRecvPci));
    if (pioRecvPci != 0)
    {
        LLOGLN(10, ("    pioRecvPci->dwProtocol %d", (int)(pioRecvPci->dwProtocol)));
        LLOGLN(10, ("    pioRecvPci->cbPciLength %d", (int)(pioRecvPci->cbPciLength)));
    }
    {
        /* Send buffer: 4(hCard) + 16(sendPci) + 4(sendLen) + cbSendLength
         * + 12(recvPci) + 4(recvLen) = 40 + cbSendLength */
        int msg_size = 64 + (int)cbSendLength + (int)*pcbRecvLength;
        msg = alloc_msg_buf(msg_size);
        if (msg == NULL)
        {
            LLOGLN(0, ("SCardTransmit: error, alloc_msg_buf"));
            return SCARD_F_INTERNAL_ERROR;
        }
    }
    offset = 0;
    SET_UINT32(msg, offset, hCard);
    offset += 4;
    SET_UINT32(msg, offset, pioSendPci->dwProtocol);
    offset += 4;
    SET_UINT32(msg, offset, pioSendPci->cbPciLength);
    offset += 4;
    extra_len = (pioSendPci->cbPciLength > 8)
                ? (int)(pioSendPci->cbPciLength - 8) : 0;
    SET_UINT32(msg, offset, extra_len);
    offset += 4;
    memcpy(msg + offset, pioSendPci + 1, extra_len);
    offset += extra_len;
    SET_UINT32(msg, offset, cbSendLength);
    offset += 4;
    memcpy(msg + offset, pbSendBuffer, cbSendLength);
    offset += cbSendLength;
    got_recv_pci = (pioRecvPci != NULL) && (pioRecvPci->cbPciLength >= 8);
    if (got_recv_pci == 0)
    {
        SET_UINT32(msg, offset, 0); /* dwProtocol */
        offset += 4;
        SET_UINT32(msg, offset, 0); /* cbPciLength */
        offset += 4;
        SET_UINT32(msg, offset, 0); /* extra_len */
        offset += 4;
    }
    else
    {
        SET_UINT32(msg, offset, pioRecvPci->dwProtocol);
        offset += 4;
        SET_UINT32(msg, offset, pioRecvPci->cbPciLength);
        offset += 4;
        extra_len = pioRecvPci->cbPciLength - 8;
        SET_UINT32(msg, offset, extra_len);
        offset += 4;
        memcpy(msg + offset, pioRecvPci + 1, extra_len);
        offset += extra_len;
    }
    SET_UINT32(msg, offset, *pcbRecvLength);
    offset += 4;
    if (send_message(SCARD_TRANSMIT, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardTransmit: error, send_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    {
        /* Response: 12(recvPci) + 4(recvLen) + recvLength + 4(status) */
        int resp_size = 24 + (int)orig_recv_len;
        int send_size = 64 + (int)cbSendLength + (int)orig_recv_len;
        bytes = resp_size > send_size ? resp_size : send_size;
    }
    code = SCARD_TRANSMIT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardTransmit: error, get_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_TRANSMIT)
    {
        LLOGLN(0, ("SCardTransmit: error, bad code"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    if (got_recv_pci == 0)
    {
        offset += 8;
        extra_len = GET_UINT32(msg, offset);
        offset += 4;
        offset += extra_len;
    }
    else
    {
        pioRecvPci->dwProtocol = GET_UINT32(msg, offset);
        offset += 4;
        pioRecvPci->cbPciLength = GET_UINT32(msg, offset);
        offset += 4;
        extra_len = GET_UINT32(msg, offset);
        offset += 4;
        offset += extra_len;
    }
    *pcbRecvLength = GET_UINT32(msg, offset);
    offset += 4;
    LLOGLN(10, ("  cbRecvLength %d", (int)*pcbRecvLength));
    if (*pcbRecvLength > orig_recv_len)
    {
        LLOGLN(0, ("SCardTransmit: error, server returned %d bytes "
                    "but buffer is only %d",
                    (int)*pcbRecvLength, (int)orig_recv_len));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    memcpy(pbRecvBuffer, msg + offset, *pcbRecvLength);
    LHEXDUMP(10, (pbRecvBuffer, *pcbRecvLength));
    offset += *pcbRecvLength;
    status = GET_UINT32(msg, offset);
    free(msg);
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardListReaderGroups(SCARDCONTEXT hContext, LPSTR mszGroups,
                      LPDWORD pcchGroups)
{
    LLOGLN(10, ("SCardListReaderGroups:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardListReaderGroups: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API LONG
SCardListReaders(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders,
                 LPDWORD pcchReaders)
{
    char *msg;
    char *reader_names;
    int reader_names_index;
    int code;
    int bytes;
    int num_readers;
    int status;
    int offset;
    int index;
    int val;
    int llen;
    char reader[100];

    LLOGLN(10, ("SCardListReaders:"));
    LLOGLN(10, ("SCardListReaders: mszGroups %s", mszGroups));
    LLOGLN(10, ("SCardListReaders: *pcchReaders %d", (int)*pcchReaders));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardListReaders: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((mszGroups == NULL) && (mszReaders == NULL))
    {
        *pcchReaders = 0;
    }
    {
        int msg_size = 12;
        if (mszGroups != 0)
        {
            msg_size += (int)strlen(mszGroups);
        }
        if (msg_size < 8192)
        {
            msg_size = 8192;
        }
        msg = alloc_msg_buf(msg_size);
        if (msg == NULL)
        {
            LLOGLN(0, ("SCardListReaders: error, alloc_msg_buf"));
            return SCARD_F_INTERNAL_ERROR;
        }
    }
    offset = 0;
    SET_UINT32(msg, offset, hContext);
    offset += 4;
    if (mszGroups != 0)
    {
        unsigned int bytes_groups = strlen(mszGroups);
        SET_UINT32(msg, offset, bytes_groups);
        offset += 4;
        memcpy(msg + offset, mszGroups, bytes_groups);
        offset += bytes_groups;
    }
    else
    {
        SET_UINT32(msg, offset, 0);
        offset += 4;
    }
    val = *pcchReaders;
    SET_UINT32(msg, offset, val);
    offset += 4;
    if (send_message(SCARD_LIST_READERS, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardListReaders: error, send_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    {
        int msg_size = 12;
        if (mszGroups != 0)
        {
            msg_size += (int)strlen(mszGroups);
        }
        if (msg_size < 8192)
        {
            msg_size = 8192;
        }
        bytes = msg_size;
    }
    code = SCARD_LIST_READERS;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardListReaders: error, get_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_LIST_READERS)
    {
        LLOGLN(0, ("SCardListReaders: error, bad code"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    llen = GET_UINT32(msg, offset);
    offset += 4;
    num_readers = GET_UINT32(msg, offset);
    offset += 4;
    LLOGLN(10, ("SCardListReaders: mszReaders %p pcchReaders %p num_readers %d",
                mszReaders, pcchReaders, num_readers));
    reader_names = (char *) g_malloc_nofail(8192);
    reader_names_index = 0;
    for (index = 0; index < num_readers; index++)
    {
        memcpy(reader, msg + offset, 100);
        bytes = strlen(reader);
        memcpy(reader_names + reader_names_index, reader, bytes);
        reader_names_index += bytes;
        reader_names[reader_names_index] = 0;
        reader_names_index++;
        offset += 100;
        LLOGLN(10, ("SCardListReaders: readername %s", reader));
    }
    reader_names[reader_names_index] = 0;
    reader_names_index++;
    status = GET_UINT32(msg, offset);
    LLOGLN(10, ("SCardListReaders: status 0x%8.8x", status));
    offset += 4;
    if (mszReaders == 0)
    {
        reader_names_index = llen / 2;
    }
    if (pcchReaders != 0)
    {
        *pcchReaders = reader_names_index;
    }
    if (mszReaders != 0)
    {
        memcpy(mszReaders, reader_names, reader_names_index);
    }
    free(msg);
    free(reader_names);
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardFreeMemory(SCARDCONTEXT hContext, LPCVOID pvMem)
{
    LLOGLN(0, ("SCardFreeMemory:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardFreeMemory: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API LONG
SCardCancel(SCARDCONTEXT hContext)
{
    char msg[256];
    int code;
    int bytes;
    int status;

    LLOGLN(10, ("SCardCancel:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardCancel: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hContext);
    if (send_message(SCARD_CANCEL, msg, 4) != 0)
    {
        LLOGLN(0, ("SCardCancel: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_CANCEL;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardCancel: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_CANCEL) || (bytes != 4))
    {
        LLOGLN(0, ("SCardCancel: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    LLOGLN(10, ("SCardCancel: got status 0x%8.8x", status));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
               LPDWORD pcbAttrLen)
{
    LLOGLN(0, ("SCardGetAttrib:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardGetAttrib: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API LONG
SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPCBYTE pbAttr,
               DWORD cbAttrLen)
{
    LLOGLN(0, ("SCardSetAttrib:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardSetAttrib: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API char *
pcsc_stringify_error(const long code)
{
    LLOGLN(10, ("pcsc_stringify_error: 0x%8.8x", (int)code));
    switch (code)
    {
        case SCARD_S_SUCCESS:
            snprintf(g_error_str, 511, "Command successful.");
            break;
        case SCARD_F_INTERNAL_ERROR:
            snprintf(g_error_str, 511, "Internal error.");
            break;
        default:
            snprintf(g_error_str, 511, "error 0x%8.8x", (int)code);
            break;
    }
    g_error_str[511] = 0;
    return g_error_str;
}
