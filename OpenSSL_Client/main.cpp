#include <iostream>
#include <string>
#include <openssl/bio.h> /* BasicInput/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */

const std::string connect_str =
  "localhost:8443";
const std::string request =
  "GET /secret.txt HTTP/1.1\n\n";
const uint64_t openssl_options =
  ( OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
    OPENSSL_INIT_ADD_ALL_CIPHERS     |
    OPENSSL_INIT_ADD_ALL_DIGESTS );

static void openssl_initialize(void)
{
  OPENSSL_init_crypto(openssl_options, NULL);
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
  ERR_get_state();
}

int main()
{
  openssl_initialize();
  SSL *ssl     = NULL;
  BIO *bio     = NULL;
  BIO *out     = NULL;
  SSL_CTX *ctx = NULL;
  uint8_t tmpbuf[1024+1];

  ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL) {
    std::cout << "FAIL: Unable to create TLS_client_method()\n";
    ERR_print_errors_fp(stdout);
    goto end;
  }

  bio = BIO_new_ssl_connect(ctx);
  if (bio == NULL) {
    std::cout << "FAIL: Unable to create a BIO chain\n";
    ERR_print_errors_fp(stdout);
    goto end;
  }

  BIO_get_ssl(bio, &ssl);
  if (ssl == NULL) {
    std::cout << "FAIL: Unable to create a BIO chain\n";
    ERR_print_errors_fp(stdout);
    goto end;
  }

  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  BIO_set_conn_hostname(bio, connect_str.c_str());

  out = BIO_new_fp(stdout, BIO_NOCLOSE);
  if (out == NULL) {
    std::cout << "FAIL: Unable to create BIO stream\n";
    ERR_print_errors_fp(stdout);
    goto end;
  }

  if (BIO_do_connect(bio) <= 0) {
    std::cout << "FAIL: Unable to connect\n";
    ERR_print_errors_fp(stdout);
    goto end;
  }

  if (BIO_do_handshake(bio) <= 0) {
    std::cout << "FAIL: Failed to establish SSL connection\n";
    ERR_print_errors_fp(stdout);
    goto end;
  }

  /* TODO: Examine SSL session parameters here */

  if (BIO_puts(bio, request.c_str()) <= 0) {
    std::cout << "FAIL: Unable to write\n";
    ERR_print_errors_fp(stdout);
    goto end;
  }


  for (;;) {
    int len = BIO_read(bio, tmpbuf, 1024);
    if (len == 0)
      break;
    else if (len < 0) {
      if (!BIO_should_retry(bio)) {
        std::cout << "FAIL: read failed\n";
        ERR_print_errors_fp(stdout);
        break;
      }
    }
    else {
      tmpbuf[len] = 0;
      BIO_write(out, tmpbuf, len);
    }
  }

 end:
  BIO_free_all(bio);
  BIO_free(out);
  return 0;
}
