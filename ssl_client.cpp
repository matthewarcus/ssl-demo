// ----------------------------------------------------------------------------
// "DO WHAT THOU WILT license" (Revision 666):
// Copyright Matthew Arcus (c) 2014.
// Please retain this notice.
// You can do whatever you like with this code.
// ----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>

#include "ssl_lib.h"

#if !defined LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER >= 0x10002000L
#define USE_ALPN
#endif

static const char *certFile = "clientcert.pem";
static const char *keyFile = "clientkey.pem";
static const char *clientcasFile = "clientcas.pem";
static const char *syscasdir = "/etc/ssl/certs";
static const char *localcasdir = "clientcerts";


static const char *username = "user";
static const char *password = "password";
//static const char *username = NULL;
//static const char *password = NULL;

#if !defined NO_SRP
// Return the SRP password
char *srpCallback(SSL *ssl, void *arg)
{
  char *user = (char*)arg;
  if (password != NULL) {
    return OPENSSL_strdup(password);
  } else {
    // getpass is 'obsolete' but does the job here
    ssize_t promptsize = 256;
    char prompt[promptsize];
    CHECK(snprintf(prompt, promptsize, "Password for %s: ", user) < promptsize);
    char *pass = getpass(prompt);
    char *result = OPENSSL_strdup(pass);
    // getpass uses a static buffer, so clear it out after use.
    memset(pass,0,strlen(pass));
    return result;
  }
}

unsigned int pskCallback(SSL *ssl, const char *hint,
			 char *identity, unsigned int max_identity_len,
			 unsigned char *psk, unsigned int max_psk_len)
{
  if (debuglevel > 2) fprintf(stderr, "PSK callback for hint '%s'\n", hint);
  CHECK(max_identity_len >= strlen(username));
  CHECK(max_psk_len >= strlen(password));
  strcpy(identity,username);
  strcpy((char*)psk,password);
  return strlen((char *)psk);
}
#endif

static int ocsp_resp_cb(SSL *s, void *arg)
{
  BIO *bio = (BIO *)arg;
  const unsigned char *p;
  int len = SSL_get_tlsext_status_ocsp_resp(s, &p);
  BIO_puts(bio, "OCSP response: ");
  if (p == NULL) {
    BIO_puts(bio, "no response sent\n");
    return 1;
  }
  OCSP_RESPONSE *rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
  if (rsp == NULL) {
    BIO_puts(bio, "response parse error\n");
    BIO_dump_indent(bio, (char *)p, len, 4);
    return 0;
  }
  BIO_puts(bio, "\n======================================\n");
  OCSP_RESPONSE_print(bio, rsp, 0);
  BIO_puts(bio, "======================================\n");
  OCSP_RESPONSE_free(rsp);
  return 1;
}

int main(int argc, char *argv[])
{
  bool anon = false;
  bool nocert = false;
  bool null = false;
  bool doSRP = false;
  bool doPSK = false;
  bool doOCSP = false;
  bool waitforpeer = false;
  int sockbuff = 0;

  const char *readSessionFile = NULL;
  const char *writeSessionFile = NULL;
  const char *cipherlist = NULL;
  const SSL_METHOD *method = SSLv23_client_method();
  const char *servername = NULL;
  const char *progname = argv[0];
  checkVersion();
#if defined USE_ALPN
  std::string alpn_protos;
#endif

  while (argc > 1) {
    // Options shared with server
    if (strcmp(argv[1],"--noecho") == 0) {
      noecho = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--debug") == 0) {
      argc--; argv++;
      debuglevel = atoi(argv[1]);
      argc--; argv++;
    } else if (strcmp(argv[1],"--SSLv3") == 0) {
      method = SSLv3_client_method();
      argc--; argv++;
    } else if (strcmp(argv[1],"--TLSv1") == 0) {
      method = TLSv1_client_method();
      argc--; argv++;
    } else if (strcmp(argv[1],"--TLSv1.1") == 0) {
      method = TLSv1_1_client_method();
      argc--; argv++;
    } else if (strcmp(argv[1],"--TLSv1.2") == 0) {
      method = TLSv1_2_client_method();
      argc--; argv++;
    } else if (strcmp(argv[1],"--cipherlist") == 0) {
      argc--; argv++;
      cipherlist = argv[1];
      argc--; argv++;
    } else if (strcmp(argv[1],"--alpn") == 0) {
#if defined USE_ALPN
      argc--; argv++;
      alpn_protos += (char)strlen(argv[1]);
      alpn_protos += argv[1];
      argc--; argv++;
#else 
      fprintf(stderr,"Error: ALPN needs OpenSSL 1.02+\n");
      exit(0);
#endif
    } else if (strcmp(argv[1],"--rfactor") == 0) {
      argc--; argv++;
      rfactor = atoi(argv[1]);
      argc--; argv++;
    } else if (strcmp(argv[1],"--sockbuff") == 0) {
      argc--; argv++;
      sockbuff = atoi(argv[1]);
      argc--; argv++;
    } else if (strcmp(argv[1],"--nocert") == 0) {
      nocert = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--wait") == 0) {
      waitforpeer = true;
      argc--; argv++;
      //  Client options
    } else if (strcmp(argv[1],"--anon") == 0) {
      anon = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--srp") == 0) {
      doSRP = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--psk") == 0) {
      doPSK = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--null") == 0) {
      null = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--ocsp") == 0) {
      doOCSP = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--readsession") == 0) {
      argc--; argv++;
      readSessionFile = argv[1];
      argc--; argv++;
    } else if (strcmp(argv[1],"--writesession") == 0) {
      argc--; argv++;
      writeSessionFile = argv[1];
      argc--; argv++;
    } else if (strcmp(argv[1],"--user") == 0) {
      argc--; argv++;
      username = argv[1];
      argc--; argv++;
    } else if (strcmp(argv[1],"--password") == 0) {
      argc--; argv++;
      password = argv[1];
      argc--; argv++;
    } else if (strcmp(argv[1],"--sni") == 0) {
      argc--; argv++;
      servername = argv[1];
      argc--; argv++;
    } else {
      break;
    }
  }
  if ( argc != 2) {
    fprintf(stderr,"usage: %s [options] <hostname>:<portnum>\n", progname);
    exit(0);
  }

  char *hostport = argv[1];

  // ignore SIGPIPE
  struct sigaction act;
  memset(&act,0,sizeof(act));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);

  if (debuglevel > 0) describeVersion();

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  // We shouldn't need to seed the RNG as we have /dev/urandom
  // but it seems prudent to check (openssl will fail anyway).
  CHECK(RAND_status() == SSL_OK);

  SSL_CTX *ctx = SSL_CTX_new(method);
  CHECK(ctx != NULL);

  // Uncomment to not worry about renegotiation and WANT_XXX
  // Actually, it's more instructive not to do this...
  //SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  
  //SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

  // And exclude SSLv2, even if a client uses it to start with
  long options = 0;
  options |= SSL_OP_NO_SSLv2;
  //options |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
  SSL_CTX_set_options(ctx, options);

#if 0
  options = 0;
  options |= SSL_OP_LEGACY_SERVER_CONNECT;
  SSL_CTX_clear_options(ctx, options);
#endif

  // Determine where we will look for trusted certificates
  CHECK(SSL_CTX_load_verify_locations(ctx, clientcasFile, NULL) == SSL_OK);
  CHECK(SSL_CTX_load_verify_locations(ctx, NULL, localcasdir) == SSL_OK);
  CHECK(SSL_CTX_load_verify_locations(ctx, NULL, syscasdir) == SSL_OK);

  // And get some certificates of our own, for if the server needs them
  if (!nocert) {
    CHECK(SSL_CTX_use_certificate_chain_file(ctx, certFile) == SSL_OK);
    CHECK(SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) == SSL_OK);
    CHECK(SSL_CTX_check_private_key(ctx) == SSL_OK);
  }

  // Turn on some extra logging
  if (debuglevel > 2) SSL_CTX_set_info_callback(ctx, infoCallback);

  // What sort of ciphersuite do we want?
  if (cipherlist == NULL) {
    if (anon) {
      // Encrypt only, no authentication
      cipherlist = "AECDH:ADH";
    } else if (null) {
    // No encryption, useful for debugging
      cipherlist = "NULL";
    } else if (doSRP) {
      cipherlist = "SRP";
    } else if (doPSK) {
      cipherlist = "PSK";
    } else {
      // Don't include SRP ciphers unless we are going to do SRP.
      // The server doesn't like it if the client includes SRP
      // ciphers but no SRP username (this is by design).
      cipherlist = "DEFAULT:!SRP";
    }
  }
  CHECK(SSL_CTX_set_cipher_list(ctx,cipherlist) == SSL_OK);

  // Setup other parameters
#if !defined NO_SRP
  if (doSRP) {
    // Use Secure Remote Password.
    CHECK(SSL_CTX_set_srp_username(ctx, (char*)username));
    SSL_CTX_set_srp_cb_arg(ctx,(void*)username);
    SSL_CTX_set_srp_client_pwd_callback(ctx, srpCallback);
  } else if (doPSK) {
    // Preshared key
    SSL_CTX_set_psk_client_callback(ctx, pskCallback);
  }
#endif

  BIO *bio = BIO_new_connect(hostport);
  CHECK(bio != NULL);
  BIO_set_nbio(bio,1);

  SSL *ssl = SSL_new(ctx);
  CHECK(ssl != NULL);
  SSL_set_bio(ssl,bio,bio); // Can't fail

  if (debuglevel > 1) showCiphers(ssl,stderr);

  if (readSessionFile) {
    readSession(ssl, readSessionFile);
    if (debuglevel > 2) fprintf(stderr, "Reading session from %s\n", readSessionFile);
  }

  BIO *stderr_bio = BIO_new_fp(stderr,0);

  // Deal with OCSP client request
  if (doOCSP) {
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb);
    SSL_CTX_set_tlsext_status_arg(ctx, stderr_bio);
  }

  if (servername != NULL) {
     SSL_set_tlsext_host_name(ssl, servername);
  }

#if defined USE_ALPN
  if (alpn_protos.length() > 0) {
     fprintf(stderr, "Setting ALPN: %s\n", alpn_protos.c_str());
     SSL_set_alpn_protos(ssl, 
                         (unsigned char *)alpn_protos.data(), 
                         alpn_protos.length());
  }
#endif

  SSL_set_connect_state(ssl);  // Can't fail, and not needed if we call SSL_connect

  CHECK(sslConnect(ssl) == SSL_OK); // Perform initial handshake synchronously

  int fd = SSL_get_fd(ssl);
  if (sockbuff > 0) setsockbuff(fd,sockbuff);
  setsighandler(true);

  if (debuglevel > 0) {
    describeConnection(ssl);
    describeSession(ssl);
  }
  if (debuglevel > 1) {
    describeCertificates(ssl,false);
  }

#if 0
  // Do this before sending any data to avoid full-duplex problems
  if (doRenegotiate) {
    // We could change cipher at this point
    //if (!null) CHECK(SSL_CTX_set_cipher_list(ctx,"RC4") == SSL_OK);
    CHECK(SSL_renegotiate(ssl) == SSL_OK);
    CHECK(sslDoHandshake(ssl) == SSL_OK);
    describeConnection(ssl);
    describeSession(ssl);
  }
#endif

  //SSL_heartbeat(ssl); // !!

  bool loopok = sslLoop(ssl,fd,false,false,waitforpeer);

  if (writeSessionFile != NULL) {
    if (debuglevel > 0) {
      fprintf(stderr, "Writing final session to %s\n",
	      writeSessionFile);
      describeSession(ssl);
    }
    writeSession(ssl, writeSessionFile);
  }

  if (loopok) LOGCHECK (doShutdown(ssl) == SSL_OK);
  if (debuglevel > 2) showcounts();

  BIO_free(stderr_bio);

  //SSL_free calls BIO_free so it's an error to do this ourselves
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  sslCleanup();
}
