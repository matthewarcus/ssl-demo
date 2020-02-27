#!/bin/sh
# Some tests for basic functionality.

TMPDIR=/tmp
DATAFILE=./ssl_server
INFILE=$TMPDIR/ssl_test_in
OUTFILE=$TMPDIR/ssl_test_out
RUNLOG=$TMPDIR/run.log

PORT=5999
serverpidfile=server.pid

if [ $VALGRIND ]
then
  SERVER="valgrind --trace-children=yes --log-file=valgrind.log.%p --leak-check=full ./ssl_server"
  CLIENT="valgrind --log-file=valgrind.log.%p --leak-check=full ./ssl_client"
else
  SERVER=./ssl_server
  CLIENT=./ssl_client
fi

killserver() {
 if [ -e $serverpidfile ]
 then
     #echo Killing server `cat $serverpidfile`
     kill -INT `cat $serverpidfile` 2>/dev/null
     rm $serverpidfile
 fi
}

check() {
    TEST=$1; FILE=$2; TEXT=$3
    (egrep "$TEXT" "$FILE" > /dev/null && echo "PASS: $TEST" ) ||
     (echo "FAIL: $TEST: not found \"$TEXT\" in $FILE:"; cat $FILE)
}

# Establish client/server connection and check that data sent
# over arrives correctly, with a variety of TLS params.

test1() {
 NAME=$1; SARGS=$2; CARGS=$3

 # Daemonizing doesn't work here with the server reading stdin
 cat $DATAFILE | (tee 2>/dev/null $INFILE) | $SERVER $SARGS $PORT >/dev/null &
 echo $! > $serverpidfile
 sleep 1
 (echo hello | $CLIENT --debug 1 --wait $CARGS localhost:$PORT >$OUTFILE 2>$RUNLOG) || 
 (echo "FAIL: $NAME client failure"; cat $RUNLOG)
 #ls -l $INFILE $OUTFILE
 (diff $INFILE $OUTFILE > /dev/null && echo "PASS: $NAME") || echo "FAIL: $NAME"
 [ $SHOWLOG ] && cat $RUNLOG
 killserver
}

test2() {
    NAME=$1; SARGS=$2; CARGS=$3
    $SERVER --daemonize --wait $SARGS $PORT >$OUTFILE
    ((echo hello; sleep 1; cat $DATAFILE) | (tee 2>/dev/null $INFILE) | $CLIENT --debug 1 $CARGS localhost:$PORT >/dev/null 2>$RUNLOG) || echo "FAIL: $NAME client failure"
    #ls -l $INFILE $OUTFILE
    (diff $INFILE $OUTFILE > /dev/null && echo "PASS: $NAME") || echo "FAIL: $NAME"
    [ $SHOWLOG ] && cat $RUNLOG
    killserver
}

testa() {
    test1 "Basic>" "" ""
    test2 "Basic<" "" ""
}

testpsk() {
    test1 "PSK1>" "--psk" "--psk --user user --password password --TLSv1.2"
    check "PSK ciphersuite 1" "$RUNLOG" "PSK-"
    test2 "PSK1<" "--psk" "--psk --user user --password password"
    test1 "PSK2>" "--psk --nocert" "--psk --user user --password password --TLSv1.2"
    check "PSK ciphersuite 2" "$RUNLOG" "PSK-"
    test2 "PSK2<" "--psk --nocert" "--psk --user user --password password"
    test1 "PSK3>" "--psk" "--psk --user user --password password --cipherlist PSK-AES256-CBC-SHA"
    test2 "PSK3<" "--psk" "--psk --user user --password password --cipherlist PSK-AES256-CBC-SHA --TLSv1.2"
    check "PSK ciphersuite 3" "$RUNLOG" "PSK-AES"
}

testsrp1() {
    test1 "SRP1>" "--srp" "--srp --user user --password password --TLSv1.2"
    check "SRP ciphersuite 1" "$RUNLOG" "SRP-"
    test2 "SRP1<" "--srp" "--srp --user user --password password"
    test1 "SRP2>" "--srp --nocert" "--srp --user user --password password"
    check "SRP ciphersuite 2" "$RUNLOG" "SRP-AES"
    test2 "SRP2<" "--srp --nocert" "--srp --user user --password password"
    check "SRP ciphersuite 3" "$RUNLOG" "SRP-AES"
    test1 "SRP3>" "--srp" "--srp --user user --password password --cipherlist SRP-AES-256-CBC-SHA --TLSv1.2"
    check "SRP ciphersuite 4" "$RUNLOG" "SRP-AES"
    test2 "SRP3<" "--srp" "--srp --user user --password password --cipherlist SRP-AES-256-CBC-SHA --TLSv1.2"
    check "SRP ciphersuite 5" "$RUNLOG" "SRP-AES"
}

testa2() {
    test1 "ecdh>" "--ecdh" "--TLSv1.2"
    check "ECDH ciphersuite 1" "$RUNLOG" "ECDHE-"
    test2 "ecdh<" "--ecdh" "--TLSv1.2"
    check "ECDH ciphersuite 2" "$RUNLOG" "ECDHE-"
    test1 "clientverify>" "--ecdh --verifyclient" "--TLSv1.2"
    # This should wait until the renegotiation has happened before sending more data
    test2 "clientverify<" "--verifyclient" "--TLSv1.2"
}

# For sensible tests, need to be able to log specific data in a
# standard form, that can then be processed appropriately.
testb() {
    NAME="Ticket"
    $SERVER --daemonize --wait $PORT > /dev/null
    cat $DATAFILE | $CLIENT --debug 1 --writesession foo.tick --TLSv1.2 localhost:$PORT 2> $RUNLOG
    #openssl sess_id -text < foo.tick
    cat $DATAFILE | $CLIENT --debug 1 --readsession foo.tick --TLSv1.2 localhost:$PORT 2>> $RUNLOG
    [ $SHOWLOG ] && cat $RUNLOG
    ([ $(grep "Session ID:" $RUNLOG | uniq | wc -l) -eq 1 ] && echo "PASS: $NAME") || echo "FAIL: $NAME"
    killserver
}

testc() {
    NAME="Session"
    $SERVER --daemonize --noticket --wait $PORT > /dev/null
    cat $DATAFILE | $CLIENT --debug 1 --writesession foo.sess --TLSv1.2 localhost:$PORT 2> $RUNLOG
    #openssl sess_id -text < foo.sess
    cat $DATAFILE | $CLIENT --debug 1 --readsession foo.sess --TLSv1.2 localhost:$PORT 2>> $RUNLOG
    [ $SHOWLOG ] && cat $RUNLOG
    ([ $(grep "Session ID:" $RUNLOG | uniq | wc -l) -eq 1 ] && echo "PASS: $NAME") || echo "FAIL: $NAME"
    killserver
}

# Check that SRP fails as expected with invalid user
testsrp2() {
    NAME="SRP invalid user"
    $SERVER --daemonize --srp --wait $PORT > /dev/null
    $CLIENT --debug 3 --srp --user invalid --password invalid --TLSv1.2 localhost:$PORT 2> $RUNLOG
    [ $SHOWLOG ] && cat $RUNLOG
    check "SRP invalid user" "$RUNLOG" "^SSL3 alert .* unknown PSK identity"
    killserver
}

teste() {
    DEBUG=0
    # Data server to client. Server renegotiating. Should work
    test1 "Renegotiate1>" "--rfactor 10" "--debug $DEBUG --TLSv1.2"
    cat $RUNLOG
    # Data client to server. Server renegotiating. Won't work
    test2 "Renegotiate1<" "--rfactor 10" "--debug $DEBUG --TLSv1.2"
    # Data server to client. Client renegotiating. Won't work
    test1 "Renegotiate2>" "" "--debug $DEBUG --rfactor 10 --TLSv1.2"

    # Data client to server. Client renegotiating. Should work
    test2 "Renegotiate2<" "" "--debug $DEBUG --rfactor 10 --TLSv1.2"
    cat $RUNLOG

    # Data server to client. Client renegotiating, won't work
    test1 "Renegotiate3>" "--rfactor 10" "--debug $DEBUG --rfactor 10 --TLSv1.2"
    # Data client to server. Server renegotiating. Won't work
    test2 "Renegotiate3<" "--rfactor 10" "--debug $DEBUG --rfactor 10 --TLSv1.2"
}

# Start with a clean slate
killserver
testa
testa2
testb
testc
teste
testpsk
testsrp1
testsrp2
