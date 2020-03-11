#include <iostream>
#include <string>
#include <openssl/bio.h> /* BasicInput/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include <openssl/ec.h> /* */

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

static void testOpenSSLClient(void)
{
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
}

static void testDerKey(void)
{
    EC_KEY *ec_key      = nullptr;
    uint32_t der_len    = 85;

    // DER ecoded elliptic curve.
    uint8_t der_buf[der_len] = {
        0x30, 0x53, 0x02, 0x01, 0x01, 0x04, 0x15, 0x02,
        0xd3, 0xe9, 0x3a, 0x0c, 0xea, 0xc0, 0x14, 0x75,
        0xe7, 0xc9, 0xb8, 0x1e, 0x7e, 0xc0, 0x92, 0x31,
        0x20, 0x28, 0xd5, 0x9a, 0xa0, 0x07, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x01, 0xa1, 0x2e, 0x03,
        0x2c, 0x00, 0x04, 0x07, 0xdb, 0x74, 0xe7, 0x95,
        0x09, 0xb3, 0x8f, 0x27, 0x19, 0x63, 0xb5, 0x52,
        0x36, 0x6b, 0x93, 0xaa, 0x98, 0x18, 0x4a, 0xc9,
        0x04, 0x8b, 0xbc, 0xf6, 0x03, 0x08, 0x5d, 0x26,
        0x84, 0xd2, 0xa5, 0x6c, 0x03, 0x10, 0x09, 0xf4,
        0xc2, 0x90, 0x00, 0xa9, 0x65
    };

    const uint8_t *tmp_ptr = der_buf;
    ec_key = d2i_ECPrivateKey(nullptr, &tmp_ptr, der_len);

    if (ec_key) {
        std::cout << "EC_KEY Generated!\n";
        EC_KEY_free(ec_key);
    } else {
        std::cout << "BAD EC_KEY!\n";
    }
}

int main()
{
  openssl_initialize();
  //testOpenSSLClient();
  testDerKey();
  
  return 0;
}
