/*
 * sig_client.c
 *
 * Author: Alec Guertin
 * University of California, Berkeley
 * CS 161 - Computer Security
 * Fall 2014 Semester
 * Project 1
 */

#include "client.h"

/* The file descriptor for the socket connected to the server. */
static int sockfd;

static void perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n);
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);
static void usage();
static void kill_handler(int signum);
static int random_int();
static void cleanup();

void print_hash(unsigned char hash[]);

int main(int argc, char **argv) {
  int err, option_index, c, clientlen, counter;
  unsigned char rcv_plaintext[AES_BLOCK_SIZE];
  unsigned char rcv_ciphertext[AES_BLOCK_SIZE];
  unsigned char send_plaintext[AES_BLOCK_SIZE];
  unsigned char send_ciphertext[AES_BLOCK_SIZE];
  aes_context enc_ctx, dec_ctx;
  in_addr_t ip_addr;
  struct sockaddr_in server_addr;
  FILE *c_file, *d_file, *m_file;
  ssize_t read_size, write_size;
  struct sockaddr_in client_addr;
  tls_msg err_msg, send_msg, rcv_msg;
  mpz_t client_exp, client_mod;
  fd_set readfds;
  struct timeval tv;

  c_file = d_file = m_file = NULL;

  mpz_init(client_exp);
  mpz_init(client_mod);

  /*
   * This section is networking code that you don't need to worry about.
   * Look further down in the function for your part.
   */

  memset(&ip_addr, 0, sizeof(in_addr_t));

  option_index = 0;
  err = 0;

  static struct option long_options[] = {
    {"ip", required_argument, 0, 'i'},
    {"cert", required_argument, 0, 'c'},
    {"exponent", required_argument, 0, 'd'},
    {"modulus", required_argument, 0, 'm'},
    {0, 0, 0, 0},
  };

  while (1) {
    c = getopt_long(argc, argv, "c:i:d:m:", long_options, &option_index);
    if (c < 0) {
      break;
    }
    switch(c) {
    case 0:
      usage();
      break;
    case 'c':
      c_file = fopen(optarg, "r");
      if (c_file == NULL) {
  perror("Certificate file error");
  exit(1);
      }
      break;
    case 'd':
      d_file = fopen(optarg, "r");
      if (d_file == NULL) {
  perror("Exponent file error");
  exit(1);
      }
      break;
    case 'i':
      ip_addr = inet_addr(optarg);
      break;
    case 'm':
      m_file = fopen(optarg, "r");
      if (m_file == NULL) {
  perror("Modulus file error");
  exit(1);
      }
      break;
    case '?':
      usage();
      break;
    default:
      usage();
      break;
    }
  }

  if (d_file == NULL || c_file == NULL || m_file == NULL) {
    usage();
  }
  if (argc != 9) {
    usage();
  }

  mpz_inp_str(client_exp, d_file, 0);
  mpz_inp_str(client_mod, m_file, 0);

  signal(SIGTERM, kill_handler);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Could not open socket");
    exit(1);
  }

  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = ip_addr;
  server_addr.sin_port = htons(HANDSHAKE_PORT);
  err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
  if (err < 0) {
    perror("Could not bind socket");
    cleanup();
  }

  /*
   * TLS HANDSHAKE 
   */

   // SEND CLIENT HELLO
  hello_message *client_hello_msg = malloc(HELLO_MSG_SIZE);
  client_hello_msg->type = CLIENT_HELLO;
  client_hello_msg->random = random_int();
  client_hello_msg->cipher_suite = TLS_RSA_WITH_AES_128_ECB_SHA256;
  int result = send_tls_message(sockfd, client_hello_msg, HELLO_MSG_SIZE);
  if (result == ERR_FAILURE) {
    perror("ERROR SENDING CLIENT HELLO. EXITING.");
    exit(1);
  }

  // RECEIVE SERVER HELLO
  printf("#### CHECK RECEIVE SERVER HELLO\n");
  hello_message *server_hello_msg = malloc(HELLO_MSG_SIZE);
  int server_hello_result = receive_tls_message(sockfd, server_hello_msg, HELLO_MSG_SIZE, SERVER_HELLO);

   // SEND CLIENT CERT
  if (server_hello_result == ERR_OK && (server_hello_msg->type == SERVER_HELLO)) {
    printf("#### SERVER HELLO WORKED! ### \n");

    cert_message *client_cert_msg = malloc(CERT_MSG_SIZE);
    client_cert_msg->type = CLIENT_CERTIFICATE;
    //read client cert into char array
    fread(client_cert_msg->cert, RSA_MAX_LEN, 1, c_file);
    send_tls_message(sockfd, client_cert_msg, CERT_MSG_SIZE);
    printf("### CLIENT CERT MESSAGE SENT \n");
  } else {
    printf("SERVER HELLO FAILED, EXITING. \n");
    exit(1);
  }

   // RECEIVE SERVER CERT
  printf("### CHECK SERVER CERT RESPONSE\n");
  cert_message *server_cert_msg = malloc(CERT_MSG_SIZE);
  int server_cert_result = receive_tls_message(sockfd, server_cert_msg, CERT_MSG_SIZE, SERVER_CERTIFICATE);
  mpz_t server_decrypted_cert;
  mpz_t server_pexp; 
  mpz_t server_pmod;
  mpz_t ca_exp, ca_mod;
  if (server_cert_result == ERR_OK) {
    printf("### SERVER CERT WORKED! \n");

    mpz_init(server_decrypted_cert);
    mpz_init(server_pexp);
    mpz_init(server_pmod);
    mpz_init(ca_exp);
    mpz_init(ca_mod);
    mpz_init_set_str(ca_exp, CA_EXPONENT, 0);
    mpz_init_set_str(ca_mod, CA_MODULUS, 0);

    decrypt_cert(server_decrypted_cert, server_cert_msg, ca_exp, ca_mod);
    char *decrypted_cert_str = calloc(BYTE_SIZE, RSA_MAX_LEN);
    mpz_get_ascii(decrypted_cert_str, server_decrypted_cert);
    printf("%s\n", decrypted_cert_str);

    get_cert_exponent(server_pexp, decrypted_cert_str);
    get_cert_modulus(server_pmod, decrypted_cert_str);

  } else {
    printf("SERVER CERT BAD RESPONSE. EXITING\n");
    exit(1);
  }

   // SEND PREMASTER SECRET 
  printf("## CREATING PREMASTER SECRET\n");
  ps_msg *client_ps_msg = malloc(PS_MSG_SIZE);
  client_ps_msg->type = PREMASTER_SECRET;
  int ps = random_int();
  mpz_t ps_rsa, ps_mpz;
  mpz_init(ps_mpz);
  mpz_init(ps_rsa);
  mpz_set_ui(ps_mpz, ps);

  // encrypt with servers public RSA key
  perform_rsa(ps_rsa, ps_mpz, server_pexp, server_pmod);
  mpz_get_str(client_ps_msg->ps, HEX_BASE, ps_rsa);
  int ps_response = send_tls_message(sockfd, client_ps_msg, PS_MSG_SIZE);
  if (ps_response == ERR_OK) {
    printf("## SENDING PS WORKED\n ");
  } else {
    printf("PS SENT GOT BAD RESPONSE. EXITING\n");
    exit(1);
  }

  // COMPUTE MASTER SECRET LOCALLY
  char *client_master_secret = calloc(SHA_BLOCK_SIZE, BYTE_SIZE);
  int client_random_int = client_hello_msg->random;
  int server_random_int = server_hello_msg->random;
  mpz_t client_ms; // to compare with server ms
  mpz_init(client_ms);
  compute_master_secret(ps, client_random_int, server_random_int, client_master_secret);
  char *hex_ms_str = calloc(SHA_BLOCK_SIZE, BYTE_SIZE); 
  hex_ms_str = hex_to_str(client_master_secret, SHA_BLOCK_SIZE);

  mpz_init_set_str(client_ms, hex_ms_str, HEX_BASE);
  gmp_printf("### CLIENT MPZFORM %Zd\n", client_ms);

  printf("### HOLD UP\n");
  print_hash((unsigned char*)client_master_secret);
  printf("\n");

  // RECEIVE MASTER SECRET 
  ps_msg *server_master_msg = malloc(PS_MSG_SIZE);
  int server_ms_response = receive_tls_message(sockfd, server_master_msg, PS_MSG_SIZE, VERIFY_MASTER_SECRET);
  if ( server_ms_response == ERR_OK) {
    printf("##GOT MASTER, TIME TO VERIFY.\n");
  } else {
    printf("SERVER MS BAD MESSAGE. EXITING\n");
    exit(1);
  }

  // VERIFY SERVER MASTER SECRET MATCHES LOCAL MASTER SECRET
  mpz_t server_ms; // to compare with local value
  mpz_init(server_ms);
  decrypt_verify_master_secret(server_ms, server_master_msg, client_exp, client_mod);
  gmp_printf("### SERVER MPZFORM %Zd\n", server_ms);

  if (mpz_cmp(server_ms, client_ms) != 0) {
    printf("SERVER AND CLIENT HAVE DIFFERENT MASTER SECRETS. BYEBYE \n");
    exit(1);
  } else {
    printf("####### HECKYAH STEPHANIE IS COOL\n");
  }
  /*
   * START ENCRYPTED MESSAGES
   */

  memset(send_plaintext, 0, AES_BLOCK_SIZE);
  memset(send_ciphertext, 0, AES_BLOCK_SIZE);
  memset(rcv_plaintext, 0, AES_BLOCK_SIZE);
  memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);

  memset(&rcv_msg, 0, TLS_MSG_SIZE);

  aes_init(&enc_ctx);
  aes_init(&dec_ctx);
  
  // YOUR CODE HERE
  // SET AES KEYS
  int what = aes_setkey_enc(&enc_ctx, (unsigned char*) client_master_secret, 128);
  int hello = aes_setkey_dec(&dec_ctx, (unsigned char*) client_master_secret, 128);

  fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
  /* Send and receive data. */
  while (1) {
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sockfd, &readfds);
    tv.tv_sec = 2;
    tv.tv_usec = 10;

    select(sockfd+1, &readfds, NULL, NULL, &tv);
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      counter = 0;
      memset(&send_msg, 0, TLS_MSG_SIZE);
      send_msg.type = ENCRYPTED_MESSAGE;
      memset(send_plaintext, 0, AES_BLOCK_SIZE);
      read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      while (read_size > 0 && counter + AES_BLOCK_SIZE < TLS_MSG_SIZE - INT_SIZE) {
  if (read_size > 0) {
    err = aes_crypt_ecb(&enc_ctx, AES_ENCRYPT, send_plaintext, send_ciphertext);
    memcpy(send_msg.msg + counter, send_ciphertext, AES_BLOCK_SIZE);
    counter += AES_BLOCK_SIZE;
  }
  memset(send_plaintext, 0, AES_BLOCK_SIZE);
  read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      }
      write_size = write(sockfd, &send_msg, INT_SIZE+counter+AES_BLOCK_SIZE);
      if (write_size < 0) {
  perror("Could not write to socket");
  cleanup();
      }
    } else if (FD_ISSET(sockfd, &readfds)) {
      memset(&rcv_msg, 0, TLS_MSG_SIZE);
      memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);
      read_size = read(sockfd, &rcv_msg, TLS_MSG_SIZE);
      if (read_size > 0) {
  if (rcv_msg.type != ENCRYPTED_MESSAGE) {
    goto out;
  }
  memcpy(rcv_ciphertext, rcv_msg.msg, AES_BLOCK_SIZE);
  counter = 0;
  while (counter < read_size - INT_SIZE - AES_BLOCK_SIZE) {
    aes_crypt_ecb(&dec_ctx, AES_DECRYPT, rcv_ciphertext, rcv_plaintext);
    printf("%s", rcv_plaintext);
    counter += AES_BLOCK_SIZE;
    memcpy(rcv_ciphertext, rcv_msg.msg+counter, AES_BLOCK_SIZE);
  }
  printf("\n");
      }
    }

  }

 out:
  close(sockfd);
  return 0;
}

/*
 * \brief                  Decrypts the certificate in the message cert.
 *
 * \param decrypted_cert   This mpz_t stores the final value of the binary
 *                         for the decrypted certificate. Write the end
 *                         result here.
 * \param cert             The message containing the encrypted certificate.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the certificate.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the certificate.
 */
void decrypt_cert(mpz_t decrypted_cert, cert_message *cert, mpz_t key_exp, mpz_t key_mod) {
  mpz_t message;
  size_t bytes_read;
  
  mpz_init(message);
  mpz_init_set_str(message, cert->cert, 0); 
  perform_rsa(decrypted_cert, message, key_exp, key_mod);
}

/*
 * \brief                  Decrypts the master secret in the message ms_ver.
 *
 * \param decrypted_ms     This mpz_t stores the final value of the binary
 *                         for the decrypted master secret. Write the end
 *                         result here.
 * \param ms_ver           The message containing the encrypted master secret.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the master secret.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the master secret.
 */
void decrypt_verify_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod) {
  // use client private key 
  mpz_t master_secret;
  mpz_init(master_secret);
  mpz_init_set_str(master_secret, ms_ver->ps, HEX_BASE);
  perform_rsa(decrypted_ms, master_secret, key_exp, key_mod);

}

/*
 * \brief                  Computes the master secret.
 *
 * \param ps               The premaster secret.
 * \param client_random    The random value from the client hello.
 * \param server_random    The random value from the server hello.
 * \param master_secret    A pointer to the final value of the master secret.
 *                         Write the end result here.
 */
void compute_master_secret(int ps, int client_random, int server_random, char *master_secret) {
  // master secret = H(PS||clientHello.random||serverhello.random||ps)
  SHA256_CTX sha_ctx;
  sha256_init(&sha_ctx);
  // generate concatenated hash
  void *ps_ptr = &ps;
  void *client_random_ptr = &client_random;
  void *server_random_ptr = &server_random;

  sha256_update(&sha_ctx, ps_ptr, INT_SIZE);
  sha256_update(&sha_ctx, client_random_ptr, INT_SIZE);
  sha256_update(&sha_ctx, server_random_ptr, INT_SIZE);
  sha256_update(&sha_ctx, ps_ptr, INT_SIZE);

  // write result to master_secret & pad
  sha256_final(&sha_ctx, (unsigned char*) master_secret);

}

/*
 * \brief                  Sends a message to the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to send
 *                         the message on.
 * \param msg              A pointer to the message to send.
 * \param msg_len          The length of the message in bytes.
 */
int send_tls_message(int socketno, void *msg, int msg_len) {
  int result; // returns bytes written
  result = write(socketno, msg, msg_len);
  if (result < 0) { 
    // perror("Error sending message to socket %d", socketno);
    fprintf(stderr, "Error sending message from socket %d\n", socketno);
    return ERR_FAILURE;
    // exit(1);
  }
  return ERR_OK;
}

/*
 * \brief                  Receieves a message from the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to receive
 *                         the message on.
 * \param msg              A pointer to where to store the received message.
 * \param msg_len          The length of the message in bytes.
 * \param msg_type         The expected type of the message to receive.
 */
int receive_tls_message(int socketno, void *msg, int msg_len, int msg_type) {
  int result;
  result = read(socketno, msg, msg_len);
  if (result < 0) {
    // perror("Error receiving message from socket %d", socketno);
    fprintf(stderr, "Error receiving message from socket %d\n", socketno);
    return ERR_FAILURE;
  }
  if ( *((int *)msg) != msg_type) {
    // look at piazza post 477
    printf("Didn't receive message type expected. GOT: %d \n",  *((int *)msg));
    return ERR_FAILURE;
  }
  return ERR_OK;
}


/*
 * \brief                Encrypts/decrypts a message using the RSA algorithm.
 *
 * \param result         a field to populate with the result of your RSA calculation.
 * \param message        the message to perform RSA on. (probably a cert in this case)
 * \param e              the encryption key from the key_file passed in through the
 *                       command-line arguments
 * \param n              the modulus for RSA from the modulus_file passed in through
 *                       the command-line arguments
 *
 * Fill in this function with your proj0 solution or see staff solutions.
 */
static void perform_rsa(mpz_t result, mpz_t message, mpz_t e, mpz_t n) {
  mpz_t zero, one, odd;
  mpz_t square, power;
  mpz_init(zero);
  mpz_init(one);
  mpz_set_str(one, "1", 10);

  if (!mpz_cmp(e, zero)) {       // if msg^0, then 1
    mpz_set_str(result, "1", 10);

  } else if (!mpz_cmp(e, one)) { // if msg^1, then msg
    mpz_add(result, message, zero);

  } else{
    mpz_init(square);
    mpz_init(power);
    mpz_init(odd);

    mpz_add(odd, one, one); // odd = 1 + 1
    mpz_div(power, e, odd); // power = e/2
    mpz_mod(odd,   e, odd); // odd = e % 2
    mpz_mul(square, message, message); // sq = msg^2 
    mpz_mod(square, square,  n); // sq = msg^2 mod n

    perform_rsa(result, square, power, n);
    if (mpz_cmp(odd, zero)) // e % 2 > 0
      mpz_mul(result, result, message);

    mpz_clear(odd);
    mpz_clear(power);
    mpz_clear(square);
  }


  mpz_mod(result, result, n);
  mpz_clear(zero);
  mpz_clear(one);
}


/* Returns a pseudo-random integer. */
static int random_int() {
  srand(time(NULL));
  return rand();
}

/*
 * \brief                 Returns ascii string from a number in mpz_t form.
 *
 * \param output_str      A pointer to the output string.
 * \param input           The number to convert to ascii.
 */
void mpz_get_ascii(char *output_str, mpz_t input) {
  int i,j;
  char *result_str;
  result_str = mpz_get_str(NULL, HEX_BASE, input);
  i = 0;
  j = 0;
  while (result_str[i] != '\0') {
    output_str[j] = hex_to_ascii(result_str[i], result_str[i+1]);
    j += 1;
    i += 2;
  }
}

/*
 * \brief                  Returns a pointer to a string containing the
 *                         characters representing the input hex value.
 *
 * \param data             The input hex value.
 * \param data_len         The length of the data in bytes.
 */
char *hex_to_str(char *data, int data_len) {
  int i;
  char *output_str = calloc(1+2*data_len, sizeof(char));
  for (i = 0; i < data_len; i += 1) {
    snprintf(output_str+2*i, 3, "%02X", (unsigned int) (data[i] & 0xFF));
  }
  return output_str;
}

/* Return the public key exponent given the decrypted certificate as string. */
void get_cert_exponent(mpz_t result, char *cert) {
  char *srch, *srch2;
  char exponent[RSA_MAX_LEN/2];
  memset(exponent, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  srch += 1;
  srch = strchr(srch, '\n');
  srch += 1;
  srch = strchr(srch, '\n');
  srch += 1;
  srch = strchr(srch, ':');
  srch += 2;
  srch2 = strchr(srch, '\n');
  strncpy(exponent, srch, srch2-srch);
  mpz_set_str(result, exponent, 0);
}

/* Return the public key modulus given the decrypted certificate as string. */
void get_cert_modulus(mpz_t result, char *cert) {
  char *srch, *srch2;
  char modulus[RSA_MAX_LEN/2];
  memset(modulus, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  srch += 1;
  srch = strchr(srch, '\n');
  srch += 1;
  srch = strchr(srch, ':');
  srch += 2;
  srch2 = strchr(srch, '\n');
  strncpy(modulus, srch, srch2-srch);
  mpz_set_str(result, modulus, 0);
}

/* Prints the usage string for this program and exits. */
static void usage() {
    printf("./client -i <server_ip_address> -c <certificate_file> -m <modulus_file> -d <exponent_file>\n");
    exit(1);
}

/* Catches the signal from C-c and closes connection with server. */
static void kill_handler(int signum) {
  if (signum == SIGTERM) {
    cleanup();
  }
}

/* Converts the two input hex characters into an ascii char. */
static int hex_to_ascii(char a, char b) {
    int high = hex_to_int(a) * 16;
    int low = hex_to_int(b);
    return high + low;
}

/* Converts a hex value into an int. */
static int hex_to_int(char a) {
    if (a >= 97) {
  a -= 32;
    }
    int first = a / 16 - 3;
    int second = a % 16;
    int result = first*10 + second;
    if (result > 9) {
  result -= 1;
    }
    return result;
}

/* Closes files and exits the program. */
static void cleanup() {
  close(sockfd);
  exit(1);
}

void print_hash(unsigned char hash[]) {
  int idx;
  for (idx = 0; idx < 32; idx++)
    printf("%02x", hash[idx]);
  printf("\n");
}
