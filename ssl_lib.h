// ----------------------------------------------------------------------------
// "DO WHAT THOU WILT license" (Revision 666):
// Copyright Matthew Arcus (c) 2014.
// Please retain this notice.
// You can do whatever you like with this code.
// ----------------------------------------------------------------------------

#if !defined SSL_LIB_H
#define SSL_LIB_H

// Many SSL functions return 1 on success, something else on failure.
// We can't treat returns as a boolean - -ve values are often used.
// Checking against 1 is usually correct, so define a constant for this.

static const int SSL_OK = 1;

// Since we are just playing around, it's handy to have an error
// checking macro we can wrap around everything.

// We aren't going to worry about resource deallocation or proper
// exception handling, as one should in a real program, we'll just
// abort on error with some diagnostics.

#define CHECK(e) ((e)?(void)(0):onError(#e,__FILE__,__LINE__,true))
#define LOGCHECK(e) ((e)?(true):(onError(#e,__FILE__,__LINE__,false),false))

extern int debuglevel;
extern int rfactor;
extern bool noecho;

void onError(const char *s, const char *file, int line, bool doabort);
void setsighandler(bool once);
void setsockbuff(int fd, int buffsize);

void describeSession(SSL *ssl);
void describeConnection(SSL* ssl);
void describeCertificates(SSL* ssl, bool isServer);
void describeSession(SSL *ssl);
void showCiphers(SSL *ssl, FILE *file);
void showcounts();

void writeSession(SSL *ssl, const char *filename);
void readSession(SSL *ssl, const char *filename);
void infoCallback(const SSL *ssl, int where, int ret);

// Synchronous versions of SSL functions
int sslDoHandshake(SSL *ssl);
int sslConnect(SSL *ssl);
int sslAccept(SSL *ssl);
int sslShutdown(SSL *ssl);

bool sslLoop(SSL *ssl, int fd, bool server, bool verify, bool waitforpeer);
int doShutdown(SSL *ssl);
void sslCleanup();
#endif
