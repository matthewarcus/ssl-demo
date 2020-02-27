## SSL Demo

Investigating openssl. I wrote this a few years ago to help me understand openssl better, so the main aim is exercising features rather any particular use.

ssl_client and ssl_server are simple single threaded client and server applications.

To run, eg:

```
$ make

$ ./ssl_server 9999 &
$ echo "Hello world" | ./ssl_client localhost:9999
$ kill %1
```

See code for further options.

makecerts script (used by makefile) makes the necessary certificates; script may be modified
to, for example, generate different types of certificate.

Modify the makefile for your desired version of openssl, by default it will
compile against your local openssl dev installation, you can set `OPENSSL` or `LIBRESSL`
in the makefile to point at a local (open|libre)ssl source tree & the build will
get headers and libraries directly from there.

```
$ make test
```

runs a simple test script.

Now updated for OpenSSL 1.1.1 and TLSv1.3 - some functionality is no longer available
in 1.3 (eg. PSK, SRP, renegotiation) , so for testing we revert to 1.2 in the client
(this results in "DEPRECATED" warnings when compiling).
