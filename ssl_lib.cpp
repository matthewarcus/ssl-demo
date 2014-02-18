#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "ssl_lib.h"

int  debuglevel = 0;
int  rfactor = 0;
bool noecho = false;

size_t NBYTES = 64*1024;
//size_t NBYTES = 1024;
//size_t NBYTES = 256;

static int read_ok_count = 0;
static int read_wantread_count = 0;
static int read_wantwrite_count = 0;
static int write_ok_count = 0;
static int write_wantread_count = 0;
static int write_wantwrite_count = 0;
static int renegotiate_count = 0;
static int select_count = 0;
static size_t nread = 0;
static size_t nwritten = 0;

void onError(const char *s, const char *file, int line, bool doabort)
{
  fprintf(stderr,"'%s' failed: %s:%d\n", s, file, line);
  ERR_print_errors_fp(stderr);
  if (doabort) abort();
}

static volatile bool terminated = false;
void sigint_handler(int)
{
  terminated = true;
}

void setsighandler(bool runonce)
{
  struct sigaction sigact;
  memset(&sigact,0,sizeof(sigact));
  sigact.sa_handler = sigint_handler;
  if (runonce) sigact.sa_flags |= SA_RESETHAND;
  CHECK(sigaction(SIGINT, &sigact, NULL) == 0);
}

void showCiphers(SSL *ssl, FILE *file)
{
  for (int i=0; ; i++) {
    const char *p = SSL_get_cipher_list(ssl,i);
    if (p == NULL) break;
    if (i != 0) fprintf(file,"\n");
    fprintf(file,"%s",p);
  }
  fprintf(file,"\n");
}

void describeConnection(SSL* ssl)
{
  char buff[128];
  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
  CHECK(cipher != NULL);
  char *desc = SSL_CIPHER_description(cipher,buff,128);
  CHECK(desc != NULL);
  fprintf(stderr,"%s\n", SSLeay_version(SSLEAY_VERSION));
  fprintf(stderr,"renegotiation: %s\n", SSL_get_secure_renegotiation_support(ssl)?"allowed":"disallowed");  
  fprintf(stderr,"%s: %s", SSL_get_version(ssl), desc);
}

void describeCertificate(int i, X509 *cert)
{
  fprintf(stderr,"%1d: Subject: ", i);
  X509_NAME_print_ex_fp(stderr,X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
  fprintf(stderr,"\n");
  fprintf(stderr,"   Issuer:  ");
  X509_NAME_print_ex_fp(stderr,X509_get_issuer_name(cert), 0, XN_FLAG_ONELINE);
  fprintf(stderr,"\n");
}

void describeCertificates(SSL* ssl, bool isServer)
{
  // Resumed sessions don't necessarily have chains (not included in session ticket)
  X509 *cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    fprintf(stderr,"No peer certificates.\n");
  } else {
    fprintf(stderr,"Peer certificates:\n");
    describeCertificate(0, cert);
    X509_free(cert);
    STACK_OF(X509) *certs = SSL_get_peer_cert_chain(ssl); // We don't have to free this apparently
    // Cached sessions may not have a chain
    if (certs != NULL) {
      // On server, chain doesn't include client certificate
      if (isServer) {
        for (int i = 0; i < sk_X509_num(certs); i++) {
          describeCertificate(i+1, sk_X509_value(certs,i));
        }
      } else {
        for (int i = 1; i < sk_X509_num(certs); i++) {
          describeCertificate(i, sk_X509_value(certs,i));
        }
      }
    }
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result == X509_V_OK) {
      fprintf(stderr,"Certificate OK\n");
    } else {
      // See 'man verify(1SSL)' for meanings of the codes
      fprintf(stderr,"Verification error %ld\n", verify_result);
      ERR_print_errors_fp(stderr);
    }
  }
}

void describeSession(SSL *ssl)
{
  SSL_SESSION *session = SSL_get_session(ssl);
  CHECK(session != NULL);

  char *s;

  s = hex_to_string(session->session_id,
                    session->session_id_length);
  fprintf(stderr, "Session ID: %s\n", s);
  OPENSSL_free(s);

  s = hex_to_string(session->sid_ctx,
                    session->sid_ctx_length);

  fprintf(stderr, "Session ID CTX: %s\n", s);
  OPENSSL_free(s);
#if 0
  if (session->tlsext_ticklen > 0) {
    s = hex_to_string(session->tlsext_tick,
                      session->tlsext_ticklen);
    fprintf(stderr, "Session Ticket: %s\n", s);
    OPENSSL_free(s);
  }
#endif
}

void writeSession(SSL *ssl, const char *filename)
{
  FILE *fd = fopen(filename,"w");
  CHECK(fd != NULL);
  // We can faff with i2d_SSL_SESSION() but this is easier
  SSL_SESSION *session = SSL_get_session(ssl);
  CHECK(session != NULL);
  PEM_write_SSL_SESSION(fd,session);
  fclose(fd);
}

void readSession(SSL *ssl, const char *filename)
{
  FILE *fd = fopen(filename,"r");
  CHECK(fd != NULL);
  // We can faff with d2i_SSL_SESSION() but this is easier.
  SSL_SESSION *session = PEM_read_SSL_SESSION(fd,NULL,0,NULL);
  CHECK(session != NULL);
  SSL_set_session(ssl, session);
  SSL_SESSION_free(session); // Decrement session refcount
  fclose(fd);
}

// Nicked straight from the SSL_CTX_set_info_callback man page.
void infoCallback(const SSL *ssl, int where, int ret)
{
  const char *str;
  int w = where & ~SSL_ST_MASK;
  if (w & SSL_ST_CONNECT) {
    str = "SSL_connect";
  } else if (w & SSL_ST_ACCEPT) {
    str = "SSL_accept";
  } else {
    str = "undefined";
  }

  if (where & SSL_CB_LOOP) {
    fprintf(stderr,"%s: %s\n",str,SSL_state_string_long(ssl));
  } else if (where & SSL_CB_ALERT) {
    str = (where & SSL_CB_READ)?"read":"write";
    fprintf(stderr, "SSL3 alert %s: %s: %s\n",
            str,
            SSL_alert_type_string_long(ret),
            SSL_alert_desc_string_long(ret));
  } else if (where & SSL_CB_EXIT) {
    if (ret == 0) {
      fprintf(stderr, "%s: failed in %s\n",
              str, SSL_state_string_long(ssl));
    } else if (ret < 0) {
      fprintf(stderr, "%s: error in %s\n",
              str, SSL_state_string_long(ssl));
    }
  } else if (where & SSL_CB_HANDSHAKE_START) {
    fprintf(stderr, "SSL3 Handshake start %d\n", ret);
  } else if (where & SSL_CB_HANDSHAKE_DONE) {
    fprintf(stderr, "SSL3 Handshake done %d\n", ret);
  } else {
    fprintf(stderr,"infoCallback: 0x%04x %d\n", where, ret);
  }
}

void sslCleanup()
{
  // Various cleanup functions
  // Maddeningly, 64 bytes still remains (see https://bugs.launchpad.net/percona-server/+bug/1205196)
  //ENGINE_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  ERR_remove_thread_state(NULL);
  EVP_cleanup();
}

// Retrying versions of the SSL I/O operations, using
// non-blocking sockets and select().
int sslWait(SSL *ssl, int ret, const char *op)
{
  int err = SSL_get_error(ssl, ret);
  bool doread;
  switch (err) {
  case SSL_ERROR_WANT_READ:
    if (debuglevel > 4) fprintf(stderr, "%s wants read\n", op);
    doread = true;
    break;
  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_CONNECT:
    if (debuglevel > 4) fprintf(stderr, "%s wants write\n", op);
    doread = false;
    break;
  default:
    return ret;
  }
  int fd = SSL_get_fd(ssl);
  fd_set fds;
  FD_ZERO(&fds); FD_SET(fd, &fds);
  if (doread) {
    ret = select(fd+1,&fds,NULL,NULL,NULL);
  } else {
    ret = select(fd+1,NULL,&fds,NULL,NULL);
  }
  assert(ret == 1);
  assert(FD_ISSET(fd, &fds));
  return SSL_OK;
}

int sslDoHandshake(SSL *ssl)
{
  while(true) {
    int ret = SSL_do_handshake(ssl);
    if (ret > 0) {
      return ret;
    } else {
      ret = sslWait(ssl,ret,"Handshake");
      if (ret < 0) return ret;
    }
  }
}

int sslConnect(SSL *ssl)
{
  while(true) {
    int ret = SSL_connect(ssl);
    if (ret >= 0) {
      return ret;
    } else {
      ret = sslWait(ssl,ret,"Connect");
      if (ret < 0) return ret;
    }
  }
}

int sslAccept(SSL *ssl)
{
  while(true) {
    int ret = SSL_accept(ssl);
    if (ret >= 0) {
      return ret;
    } else {
      ret = sslWait(ssl,ret,"Accept");
      if (ret < 0) return ret;
    }
  }
}

int sslShutdown(SSL *ssl)
{
  //assert(!SSL_renegotiate_pending(ssl));
  while (true) {
    int ret = SSL_shutdown(ssl);
    if (ret >= 0) {
      return ret;
    } else {
      ret = sslWait(ssl,ret,"Shutdown");
      if (ret < 0) {
	return ret;
      }
    }
  }
}

int doShutdown(SSL *ssl)
{
  // Recommended sequence for clean shutdown (with close_notify being
  // sent in both directions).
  int ret = sslShutdown(ssl);
  if (ret == SSL_OK) return ret;
  for (int i = 0; i < 10; i++) {
    ret = sslShutdown(ssl);
    if (ret == SSL_OK) break;
    // If there is unread data queued before the peer close notify
    // we seem to get a SYSCALL error, so retry...
    // A real SYSCALL error hopefully will set errno.
    int err = SSL_get_error(ssl,ret);
    if (ret == 0 || err != SSL_ERROR_SYSCALL || errno != 0) break;
    fprintf(stderr,"Trying to shutdown\n");
  }
  return ret;
}

void showcounts()
{
  fprintf(stderr,"read_ok_count: %d\n", read_ok_count);
  fprintf(stderr,"read_wantread_count: %d\n", read_wantread_count);
  fprintf(stderr,"read_wantwrite_count: %d\n", read_wantwrite_count);
  fprintf(stderr,"write_ok_count: %d\n", write_ok_count);
  fprintf(stderr,"write_wantread_count: %d\n", write_wantread_count);
  fprintf(stderr,"write_wantwrite_count: %d\n", write_wantwrite_count);
  fprintf(stderr,"select_count: %d\n", select_count);
  fprintf(stderr,"renegotiate_count: %d\n", renegotiate_count);
  fprintf(stderr,"bytes read: %zu\n", nread);
  fprintf(stderr,"bytes written: %zu\n", nwritten);
}

void setsockbuff(int fd, int buffsize)
{
  // For testing, set the buffer sizes of a socket to small
  // I suppose
  int size = buffsize;
  socklen_t ssize = sizeof(size);
  CHECK(setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,ssize) == 0);
  CHECK(setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&size,ssize) == 0);
  CHECK(getsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,&ssize) == 0);
  if (debuglevel > 1) fprintf(stderr,"RCV buffer now %d\n", size);
  CHECK(getsockopt(fd,SOL_SOCKET,SO_SNDBUF,&size,&ssize) == 0);
  if (debuglevel > 1) fprintf(stderr,"SND buffer now %d\n", size);
}

// Initiate an asynchronous renegotiation
void renegotiate(SSL *ssl, bool server)
{
  if (debuglevel > 2) fprintf(stderr,"Renegotiating\n");
  CHECK(SSL_renegotiate(ssl) == SSL_OK);
  // On server, this results in "HelloRequest" being sent to server.
  // Allow SSL to do this in its own time on client.
  if (server) {
    CHECK(sslDoHandshake(ssl) == SSL_OK);
  }
}

void renegotiatefull(SSL *ssl, bool server)
{
  if (debuglevel > 2) fprintf(stderr,"Renegotiating\n");
  CHECK(SSL_renegotiate(ssl) == SSL_OK);
  // On server, this results in "HelloRequest" being sent to server.
  // Allow SSL to do this in its own time on client.
  CHECK(sslDoHandshake(ssl) == SSL_OK);
  if (server) {
    // Nasty hack - this makes SSL expect an immediate
    // handshake and we get an error otherwise. See:
    // http://www.mail-archive.com/openssl-users@openssl.org/msg20802.html
    ssl->state = SSL_ST_ACCEPT;
    // Complete the handshake.
    // This fails if there is unread data from the client
    CHECK(sslDoHandshake(ssl) == SSL_OK);
  }
}

// Called after client verification. Return value indicates if connection
// should be closed.
int verifyCallback(int preverify_ok, X509_STORE_CTX *ctx)
{
  return 1;
}

bool sslLoop(SSL *ssl, int fd, bool isserver, bool verify)
{
  char inbuffer[NBYTES+1]; // Want to null terminate
  char netbuffer[NBYTES];

  size_t insize = 0, instart = 0;
  bool read_wantwrite = false; // set if last read return want_write
  bool write_wantread = false; // set if last write returned want_read
  bool closed = false; // stdin has closed
  terminated = false;  // global flag set by signal handler
  while (!terminated || SSL_renegotiate_pending(ssl)) {
    bool write_pending = insize > 0;
    fd_set rfds, wfds;
    FD_ZERO(&rfds); FD_ZERO(&wfds);
    // Suppress ingest of data if we are renegotiating
    if (!closed && !write_pending && !SSL_renegotiate_pending(ssl)) {
      FD_SET(0, &rfds);
    }
    if (!write_pending) {
      if (!read_wantwrite) {
	FD_SET(fd, &rfds);
      } else {
	FD_SET(fd, &wfds);
      }
    }
    if (write_pending) {
      if (write_wantread) {
	FD_SET(fd, &rfds);
      } else {
	FD_SET(fd, &wfds);
      }
    }
    {
      int ret = select(fd+1,&rfds,&wfds,NULL,NULL);
      if (ret < 0 && errno == EINTR) continue; // Recheck loop condition
      select_count++;
      CHECK(ret >= 0);
    }
    if (FD_ISSET(0, &rfds)) {
      size_t ret = read(0, inbuffer,NBYTES);
      if (debuglevel > 2) fprintf(stderr,"Read %zd bytes from 0\n", ret);
      CHECK(ret >= 0);
      if (ret <= 0) {
	closed = true;
	// This implements the rule that we close the connection when
	// the server stops reading input. Other strategies are possible.
	if (isserver) return true;
      } else {
	inbuffer[ret] = 0;
	if (strcmp(inbuffer, "r\n") == 0) {
	  renegotiatefull(ssl,isserver);
	} else {
	  insize = ret;
	  instart = 0;
	}
      }
    }
    bool gotevent = FD_ISSET(fd, &rfds) || FD_ISSET(fd, &wfds);
    // If we aren't waiting to complete a write.
    // we must be waiting to read.
    if (!write_pending && gotevent) {
      while (true) {
	int ret = SSL_read(ssl, netbuffer, NBYTES);
	int err = SSL_get_error(ssl,ret);
	if (ret == 0) {
	  return err == SSL_ERROR_ZERO_RETURN;
	} else if (ret > 0) {
	  CHECK(err == SSL_ERROR_NONE);
	  if (debuglevel > 2) fprintf(stderr,"Read %d bytes from SSL\n", ret);
	  read_ok_count++;
	  nread += ret;
	  if (!noecho) CHECK(write(1,netbuffer,ret) > 0);
	  if (verify) {
	    // On first read from client, do SRP/PSK verification
	    assert(isserver);
	    verify = false;
	    if (debuglevel > 0) fprintf(stderr,"Verifying client\n");
	    SSL_set_verify(ssl, 
			   SSL_VERIFY_PEER |
			   //SSL_VERIFY_CLIENT_ONCE |
			   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			   verifyCallback);
	    renegotiatefull(ssl,isserver);
	    if (debuglevel > 2) fprintf(stderr,"Client verified\n");
	  }
	} else {
	  if (err == SSL_ERROR_WANT_READ) {
	    read_wantread_count++;
	    read_wantwrite = false;
	  } else if (err == SSL_ERROR_WANT_WRITE) {
	    read_wantwrite_count++;
	    read_wantwrite = true;
	  } else {
	    CHECK(0);
	  }
	  break; // On error return
	}
      }
    }
    // We might have done some reads or writes to the socket in
    // the calls to SSL_read, so it's not clear that the various
    // flags are still valid at this point. So just
    // call SSL_write unconditionally & keep the logic simple (if we
    // didn't do a read, then we must have got the flags for write, if
    // we did, then the state might have changed), and if we didn't get
    // signalled on the SSL fd at all, we must have got something in
    // from stdin.
    // If write_pending is true, then we won't have tried to read &
    // so it's only worth trying a write if we got an event.
    if (insize > 0 && !(write_pending && !gotevent)) {
      int ret = SSL_write(ssl, inbuffer+instart, insize);
      if (ret == 0) {
	return true;
      } else if (ret > 0) {
	if (debuglevel > 2) fprintf(stderr,"Write %d bytes to SSL\n", ret);
	// Allow for partial writes
	insize -= ret;
	instart += ret;
	nwritten += ret;
	write_wantread = false;
	write_ok_count++;
      } else {
	int err = SSL_get_error(ssl,ret);
	if (err == SSL_ERROR_WANT_READ) {
	  write_wantread = true;
	  write_wantread_count++;
	} else if (err == SSL_ERROR_WANT_WRITE) {
	  write_wantread = false;
	  write_wantwrite_count++;
	} else {
	  CHECK(0);
	}
      }
    }
    // Now maybe start a random renegotiation
    if (!verify && insize == 0 && rfactor > 0 && rand()%rfactor == 0) {
      renegotiate_count++;
      renegotiate(ssl,isserver);
    }
  }
  return true;
}
