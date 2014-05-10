// ----------------------------------------------------------------------------
// "DO WHAT THOU WILT license" (Revision 666):
// Copyright Matthew Arcus (c) 2014.
// Please retain this notice.
// You can do whatever you like with this code.
// ----------------------------------------------------------------------------

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/srp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "ssl_lib.h"

static bool verbose = false;

static const char *chainfile = "serverchain.pem";
static const char *keyfile = "serverkey.pem";
static const char *servercasfile = "servercas.pem";
static const char *dhparamfile = "dhparam.pem";

// openssl ecparam -list_curves to find more or look
// at /usr/include/openssl/obj_mac.h
int eccurve = NID_secp256k1;
//int eccurve = NID_X9_62_prime256v1;

static const char *username = "user";
static const char *password = "password";

static const char *srpgroup = "1536";
static const char *srpvfile = "passwd.srpv";

static int sockbuff = 0;

void setupClientVerification(SSL_CTX* ctx, const char *caFile)
{
  STACK_OF(X509_NAME) *cert_names = SSL_load_client_CA_file(caFile);
  CHECK(cert_names != NULL);
  SSL_CTX_set_client_CA_list(ctx, cert_names);
  // Default is to terminate connection on verification failure,
  // so use our own callback.
  // Now we set this during renegotiation
  //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verifyCallback); // No return value
}

void setupDH(SSL_CTX *ctx)
{
  DH *dh;
  FILE *fp = fopen(dhparamfile,"r");
  if (fp == NULL) {
    if (debuglevel > 0) fprintf(stderr,"Generating DH params\n");
    dh = DH_generate_parameters(256,5,NULL,NULL);
  } else {
    if (debuglevel > 0) fprintf(stderr,"Reading DH params from %s\n", dhparamfile);
    dh = PEM_read_DHparams(fp,NULL,NULL,NULL);
    fclose(fp);
  }
    
  CHECK(dh != NULL);

  // Check we have suitable DH parameters
  int codes = 0;
  CHECK(DH_check(dh,&codes));
  if (codes != 0) fprintf(stderr,"DH_check: codes=0x%02x\n", codes);

  CHECK(SSL_CTX_set_tmp_dh(ctx,dh) == SSL_OK);
  DH_free(dh);
}

// Set up parameters for ephemeral elliptic curve Diffie-Helman.
// For maximum Forward Secrecy
// Get an EC_KEY from the serverkey.pem file if possible
// Else generate a new one.
void setupECDH(SSL_CTX *ctx)
{
  EC_KEY *ecdh = NULL;
  // Try and read an EC key from the serverkey file.
  // If no file, or it's not a valid EC key, generate a new one.
  FILE *fp = fopen(keyfile,"r");
  if (fp != NULL) {
    ecdh = PEM_read_ECPrivateKey(fp,NULL,NULL,NULL);
    fclose(fp);
  }
  if (ecdh != NULL) {
    if (debuglevel > 0) fprintf(stderr,"Reading EC key from %s\n", keyfile);
  } else {
    if (debuglevel > 0) fprintf(stderr,"Generating EC params\n");
    ecdh = EC_KEY_new_by_curve_name(eccurve);
    CHECK(ecdh != NULL);
  }
    
  CHECK(SSL_CTX_set_tmp_ecdh(ctx, ecdh) == SSL_OK);
  EC_KEY_free(ecdh);
}

char *bn2hex(const BIGNUM *bn, char *&tmp)
{
  if (tmp != NULL) OPENSSL_free(tmp);
  tmp = BN_bn2hex(bn);
  return tmp;
}

//// SRP ////

// Load SRP verifier data in here when needed
static SRP_VBASE *srpData = NULL;
static bool doSRPData = false;

// What is ad here?
int srpServerCallback(SSL *s, int *ad, void *arg)
{
  (void)arg;

  // Simulate asynchronous loading of SRP data
  // The first time this is called, we return -1 and get an WANT_X509_LOOKUP
  // error in the handshake; we then set up the SRP user data externally and
  // try again, this time it should succeed.
  if (srpData == NULL) {
    if (debuglevel > 0) fprintf(stderr,"Deferring SRP data\n");
    doSRPData = true;
    return -1; // Not ready yet
  }

  // srpData has been initialized, so get username.
  char *srpusername = SSL_get_srp_username(s);
  CHECK(srpusername != NULL);
  if (debuglevel > 0) fprintf(stderr, " username = %s\n", srpusername);
  // Get data for user
  SRP_user_pwd *p = SRP_VBASE_get_by_user(srpData,srpusername);
  if (p == NULL) {
    fprintf(stderr, "User %s doesn't exist\n", srpusername);
    return SSL3_AL_FATAL;
  }
  if (debuglevel > 1) {
    char *tmp = NULL;
    fprintf (stderr, " g = %s\n", bn2hex(p->g,tmp));
    fprintf (stderr, " N = %s\n", bn2hex(p->N,tmp));
    fprintf (stderr, " salt = %s\n", bn2hex(p->s,tmp));
    fprintf (stderr, " verifier = %s\n", bn2hex(p->v,tmp));
    OPENSSL_free(tmp);
  }

  // Set verifier data
  CHECK(SSL_set_srp_server_param(s, p->N, p->g, p->s, p->v, NULL) == SSL_OK);
  return SSL_ERROR_NONE;
}


void setupSRPData(SSL_CTX *ctx)
{
  assert(srpData == NULL);
  // For convenience, we will use the SRP_VBASE structure
  // I'm not entirely sure what all the fields do, but
  // we mainly want it for the stack of user data.
  srpData = SRP_VBASE_new(NULL);
  CHECK(srpData != NULL);
  // Try reading in off disk.
  if (SRP_VBASE_init(srpData, (char *)srpvfile) != 0) {
    // No file to initialize from so make our own entry
    // This would normally have already been done.
    SRP_user_pwd *p = (SRP_user_pwd *)OPENSSL_malloc(sizeof(SRP_user_pwd));

    // Get prime and generator. These don't have to be secret, so use
    // some predefined good values.
    SRP_gN *gN = SRP_get_default_gN(srpgroup);
    CHECK(gN != NULL);
    // This check seems a bit pointless, but doesn't do harm.
    char *srpCheck = SRP_check_known_gN_param(gN->g, gN->N); 
    CHECK(srpCheck != NULL);
    if (debuglevel > 0) fprintf(stderr, "SRP check: %s\n", srpCheck);

    // Now create the verifier for the password.
    // We could get the password from the user at this point.
    BIGNUM *salt = NULL, *verifier = NULL;
    CHECK(SRP_create_verifier_BN(username, password, &salt, &verifier, gN->N, gN->g));
    p->id = OPENSSL_strdup(username);
    p->g = gN->g; p->N = gN->N;
    p->s = salt; p->v = verifier;
    p->info = NULL;
    // Add in to VBASE stack of user data
    sk_SRP_user_pwd_push(srpData->users_pwd, p);
  }
}

void setupSRP(SSL_CTX *ctx)
{
  //CHECK(SSL_CTX_set_srp_cb_arg(ctx, srpData) == SSL_OK);
  CHECK(SSL_CTX_set_srp_username_callback(ctx, srpServerCallback) == SSL_OK);
}

//// PSK ////

unsigned int pskServerCallback(SSL *ssl, const char *identity,
			       unsigned char *psk, unsigned int max_psk_len)
{
  if (debuglevel > 0) fprintf(stderr, "PSK callback for identity '%s'\n", identity);
  CHECK(max_psk_len >= strlen(password));
  strcpy((char*)psk, password);
  return strlen(password);
}

void setupPSK(SSL_CTX *ctx)
{
  CHECK(SSL_CTX_use_psk_identity_hint(ctx, "username") == SSL_OK);
  SSL_CTX_set_psk_server_callback(ctx, pskServerCallback);
}

bool peerVerified(SSL *ssl)
{
  X509 *cert = SSL_get_peer_certificate(ssl);
  bool result = cert != NULL && SSL_get_verify_result(ssl) == X509_V_OK;
  X509_free(cert);
  return result;
}

//// Handle a single connection ////
void doConnection(SSL_CTX *ctx, BIO *bio, bool doVerify)
{
  // This is a combination of synchronous and asynchronous I/O
  // The sockets themselves are non-blocking but for handshakes
  // & shutdown we wrap them in a select loop. Normal reading &
  // writing is multiplexed with non-socket I/O.
  // We could make everything properly event driven with a simple
  // state machine, but I wanted to understand the basic event
  // sequencing first.
  // BIO_set_nbio(bio,1); // non-blocking - done with server socket now
  SSL *ssl = SSL_new(ctx);
  CHECK(ssl != NULL);
  SSL_set_bio(ssl,bio,bio);
  SSL_set_accept_state(ssl);

  while (true) {
    int res = sslAccept(ssl); // Our 'synchronous' function
    if (res == SSL_OK) {
      break;
    } else if (SSL_get_error(ssl,res) == SSL_ERROR_WANT_X509_LOOKUP && doSRPData) {
      // Should use some sort of callback here.
      if (debuglevel > 0) fprintf(stderr, "Setting up SRP Data\n");
      setupSRPData(ctx);
      doSRPData = false;
    } else {
      fprintf(stderr,"Server SSL_accept failed: %d\n", SSL_get_error(ssl,res));
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      return;
    }
  }

  if (verbose) {
    describeConnection(ssl);
    describeSession(ssl);
    describeCertificates(ssl,true);
  }

  // Trying to verify the client when we are doing SRP isn't
  // necessary and doesn't work.
  bool isSRP = SSL_get_srp_username(ssl) != NULL;
  bool verify = doVerify && !isSRP && !peerVerified(ssl);

  int fd = SSL_get_fd(ssl);
  if (sockbuff > 0) setsockbuff(fd,sockbuff);

  // sslLoop returns false if the socket closed
  // abruptly, in which case, don't try SSL_shutdown.
  bool loopok = sslLoop(ssl,fd,true,verify);

  if (verify) {
    if (debuglevel > 0) fprintf(stderr,"Server renegotiated for client verification:\n");
    describeSession(ssl);
    describeCertificates(ssl,true);
  }
  if (debuglevel > 0) fprintf(stderr, "Closing connection\n");
  if (loopok) LOGCHECK (doShutdown(ssl) == SSL_OK);
  if (debuglevel > 0) showcounts();
  SSL_free(ssl);
}

int main(int argc, char *argv[])
{
  bool nocert = false;
  bool noticket = false;
  bool verify_client = false;
  bool doDH = false;    // Diffie-Helman key exchange
  bool doECDH = false;  // Elliptic curve Diffie-Helman
  bool doPSK = false;   // Pre-shared key
  bool doSRP = false;   // Secure remote password
  bool once = false;    // Serve just one connection, eg. for valgrind test
  // Allow ADH/AECDH/SRP as well as NULL for testing
  const char *cipherlist = "ALL:NULL";

  const SSL_METHOD *method = SSLv23_server_method();
  while (argc > 1) {
    // Options shared with client
    if (strcmp(argv[1],"-v") == 0) {
      verbose = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--noecho") == 0) {
      noecho = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--debug") == 0) {
      argc--; argv++;
      debuglevel = atoi(argv[1]);
      argc--; argv++;
    } else if (strcmp(argv[1],"--SSLv3") == 0) {
      method = SSLv3_server_method();
      argc--; argv++;
    } else if (strcmp(argv[1],"--TLSv1") == 0) {
      method = TLSv1_server_method();
      argc--; argv++;
    } else if (strcmp(argv[1],"--TLSv1.1") == 0) {
      method = TLSv1_1_server_method();
      argc--; argv++;
    } else if (strcmp(argv[1],"--TLSv1.2") == 0) {
      method = TLSv1_2_server_method();
      argc--; argv++;
    } else if (strcmp(argv[1],"--cipherlist") == 0) {
      argc--; argv++;
      cipherlist = argv[1];
      argc--; argv++;
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
      // Server options
    } else if (strcmp(argv[1],"--noticket") == 0) {
      noticket = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--verifyclient") == 0) {
      verify_client = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--dh") == 0) {
      doDH = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--ecdh") == 0) {
      doECDH = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--srp") == 0) {
      doSRP = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--psk") == 0) {
      doPSK = true;
      argc--; argv++;
    } else if (strcmp(argv[1],"--once") == 0) {
      once = true;
      argc--; argv++;
    } else {
      break;
    }
  }
  if ( argc != 2 ) {
    fprintf(stderr, "Usage: %s [-a] <portnum>\n", argv[0]);
    exit(0);
  }

  char *portnum = argv[1];

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  // We shouldn't need to seed the RNG as we have /dev/urandom
  CHECK(RAND_status() == SSL_OK);

  SSL_CTX *ctx = SSL_CTX_new(method);
  CHECK(ctx != NULL);

  //SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  //SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

  //SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
  // Disable caching of freed buffers
  //ctx->freelist_max_len = 0;

  long options = 0;
  options |= SSL_OP_NO_SSLv2;
  // Avoids a nasty hack involving using a different session id context
  // when renegotiating a connection with client verification.
  options |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
  // Don't use stateless session reuse, but old-style session ids.
  if (noticket) options |= SSL_OP_NO_TICKET;
  if (doDH) options |= SSL_OP_SINGLE_DH_USE; // Nothing to check here

  //options |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;

  SSL_CTX_set_options(ctx, options);

  CHECK(SSL_CTX_set_cipher_list(ctx,cipherlist) == SSL_OK);

  if (doDH) setupDH(ctx);
  if (doECDH) setupECDH(ctx);
  if (doSRP) setupSRP(ctx);
  if (doPSK) setupPSK(ctx);
  if (verify_client) setupClientVerification(ctx, servercasfile);
  
  CHECK(SSL_CTX_load_verify_locations(ctx, servercasfile, NULL) == SSL_OK);
  
  if (!nocert) {
    CHECK(SSL_CTX_use_certificate_chain_file(ctx, chainfile) == SSL_OK);
    CHECK(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) == SSL_OK);
    CHECK(SSL_CTX_check_private_key(ctx) == SSL_OK);
  }

  const char *context = "INIT";
  CHECK(SSL_CTX_set_session_id_context(ctx, 
				       (const unsigned char*)context, 
				       strlen(context)) == SSL_OK);

  if (verbose) SSL_CTX_set_info_callback(ctx, infoCallback);

  BIO *server = BIO_new_accept(portnum);
  CHECK(server != NULL);
  CHECK(BIO_set_bind_mode(server, BIO_BIND_REUSEADDR) == SSL_OK);
  //BIO_set_nbio_accept(server,1); // non-blocking accepts
  BIO_set_nbio(server,1); // non-blocking client sockets

  setsighandler(false); // Handle sigint

  // First accept is like listen.
  int ret = BIO_do_accept(server);
  if (ret <= 0) {
    fprintf(stderr,"BIO_do_accept\n");
  } else {
    do { 
      // Second accept is like accept.
      if (BIO_do_accept(server) <= 0) break;
      BIO *bio = BIO_pop(server);
      CHECK(bio != NULL);
      doConnection(ctx, bio, verify_client);
    } while (!once);
  }
  BIO_free(server);

  if (srpData != NULL) SRP_VBASE_free(srpData);
  SSL_CTX_free(ctx);
  sslCleanup();
}
