
/*
** server.c -- a stream socket server demo
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <mysql/mysql.h>

// for using asprintf

// the configured options and settings for the server
#define Server_VERSION_MAJOR @Server_VERSION_MAJOR@
#define Server_VERSION_MINOR @Server_VERSION_MINOR@

#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold
#define MAXDATASIZE 100

RSA *r = NULL;
MYSQL *con;

void sigchld_handler(int s)
{
  // waitpid() might overwrite errno, so we save and restore it:
  int saved_errno = errno;

  while(waitpid(-1, NULL, WNOHANG) > 0);

  errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int generate_key_pair()
{
  // return variable used for checking success
	int	ret = 0;
  // variable used to store random numbers
	BIGNUM *bne = NULL;

	int	bits = 2048;
	unsigned long	e = RSA_F4;

	// seed the random number generator
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

  // generate a new RSA key pair, and store the result in r
	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}

	// free the memory of everything
free_all:

	BN_free(bne);

	return (ret == 1);
}

void writeAccount(uint32_t *id, char *key, char *username, char *display, char * email)
{
  char *query;
  int size = asprintf(&query, "INSERT INTO reserve (public_key, username, display, email) VALUES ('%s','%s','%s','%s');\0",
           key, username, display, email);
  if (mysql_query(con, query)) {
    fprintf(stderr, "%s\n", mysql_error(con));
    exit(1);
  }

  *id = (uint32_t)mysql_insert_id(con);

  free(query);
  printf("server: wrote to database\n");
}

int createAccount(int sockfd, int numbytes)
{
  char *pub_key = "public key\0";
  if (send(sockfd, pub_key, 12, 0) == -1)
    perror("send");

  printf("server: sent public key\n");

  char *ptr;
  char key[545];
  char username[MAXDATASIZE];
  char display[MAXDATASIZE];
  char email[MAXDATASIZE];

  // client public key
  if ((numbytes = recv(sockfd, key, 544, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  if (send(sockfd, "_", 1, 0) == -1)
    perror("send");

  printf("server: received key '%s'\n", key);

  // username
  if ((numbytes = recv(sockfd, username, MAXDATASIZE-1, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  ptr = strchr(username, '\n');
  if (ptr != NULL)
    *ptr = '\0';
  if (send(sockfd, "_", 1, 0) == -1)
    perror("send");

  printf("server: received username '%s'\n", username);

  // display name
  if ((numbytes = recv(sockfd, display, MAXDATASIZE-1, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  ptr = strchr(display, '\n');
  if (ptr != NULL)
    *ptr = '\0';
  if (send(sockfd, "_", 1, 0) == -1)
    perror("send");

  printf("server: received display name '%s'\n", display);

  // email
  if ((numbytes = recv(sockfd, email, MAXDATASIZE-1, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  ptr = strchr(email, '\n');
  if (ptr != NULL)
    *ptr = '\0';
  if (send(sockfd, "_", 1, 0) == -1)
    perror("send");

  printf("server: received email '%s'\n", email);

  uint32_t id;
  writeAccount(&id, key, username, display, email);

  uint32_t networkOrderID = htonl(id);
  if (send(sockfd, &networkOrderID, sizeof(uint32_t), 0) == -1)
    perror("send");

  printf("server: sent ID\n");

  return 0;
}

void createTransaction(uint32_t *id, char *value, char *operator, char *memo, uint8_t *linked,
                       uint8_t *executed, char *transactionType, char *name, uint8_t *expirable,
                       char *expirationDate, uint32_t *coolDown, uint8_t *repeatable)
{
  char *query;
  int size = asprintf(&query, "INSERT INTO transaction (value, operator, memo, linked, executed, transactionType, name, expirable, expirationDate, coolDown, repeatable) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);\0",
                      value, operator, memo, linked, executed, transactionType, name, expirable,
                      expirationDate, coolDown, repeatable);
  if (mysql_query(con, query)) {
    fprintf(stderr, "%s\n", mysql_error(con));
    exit(1);
  }

  *id = (uint32_t)mysql_insert_id(con);

  free(query);
  printf("server: wrote to database\n");
}

void linkEntityAndTransaction(uint32_t transactionID, uint32_t entityID)
{
  char *query;
  int size = asprintf(&query, "INSERT INTO transactionGroup (entityID, transactionID) VALUES ('%d', '%d');\0",
                      entityID,
                      transactionID);
  if (mysql_query(con, query)) {
    fprintf(stderr, "%s\n", mysql_error(con));
    exit(1);
  }

  free(query);
  printf("server: wrote to database\n");
}

int updateTransaction(int sockfd, int numbytes)
{
  uint32_t id;
  char value[100];
  char operator[2];
  char type[2];
  char timestamp[100];
  char memo[100];
  char name[100];
  uint8_t linked = 0;
  uint8_t executed = 0;
  uint8_t expirable = 0;
  char expiration[100];
  uint32_t cooldown;
  uint8_t repeatable = 0;
  if ((numbytes = recv(sockfd, &id, sizeof(uint32_t), 0)) == -1) {
    perror("recv");
    exit(1);
  }
  if (id == 0) {
    // create the transaction
    if (send(sockfd, "r", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, &id, sizeof(uint32_t), 0)) == -1) { // id
      perror("recv");
      exit(1);
    }
    printf("ID: %d\n", id);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, value, 100, 0)) == -1) { // value
      perror("recv");
      exit(1);
    }
    printf("Value: %s\n", value);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, operator, 1, 0)) == -1) { // operator
      perror("recv");
      exit(1);
    }
    operator[2] = '\0';
    printf("Operator: %s\n", operator);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, name, 100, 0)) == -1) { // name
      perror("recv");
      exit(1);
    }
    printf("Name: %s\n", name);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, type, 1, 0)) == -1) { // type
      perror("recv");
      exit(1);
    }
    type[2] = '\0';
    printf("Type: %s\n", type);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, timestamp, 100, 0)) == -1) { // timestamp
      perror("recv");
      exit(1);
    }
    printf("Timestamp: %s\n", timestamp);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, memo, 100, 0)) == -1) { // memo
      perror("recv");
      exit(1);
    }
    printf("Memo: %s\n", memo);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, &linked, sizeof(uint8_t), 0)) == -1) { // linked
      perror("recv");
      exit(1);
    }
    printf("Linked: %s", linked);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, &executed, sizeof(uint8_t), 0)) == -1) { // executed
      perror("recv");
      exit(1);
    }
    printf("Executed: %s", executed);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, &expirable, 1, 0)) == -1) { // expirable
      perror("recv");
      exit(1);
    }
    printf("Expirable: %s", expirable);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, expiration, 100, 0)) == -1) { // expiration
      perror("recv");
      exit(1);
    }
    printf("Expiration: %s", expiration);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, &cooldown, sizeof(uint32_t), 0)) == -1) { // cooldown
      perror("recv");
      exit(1);
    }
    printf("Cooldown: %d", cooldown);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    if ((numbytes = recv(sockfd, &repeatable, sizeof(uint8_t), 0)) == -1) { // repeatable
      perror("recv");
      exit(1);
    }
    printf("Repeatable: %s", repeatable);
    createTransaction(&id, value, operator, memo, &linked, &executed, type, name, &expirable, expiration, &cooldown, &repeatable);
    printf("Created Transaction");
    if (send(sockfd, &id, sizeof(uint32_t), 0) == -1)
      perror("send");
    uint32_t count;
    if ((numbytes = recv(sockfd, &count, sizeof(uint32_t), 0)) == -1) {
      perror("recv");
      exit(1);
    }
    printf("Count: %d", count);
    if (send(sockfd, "_", 1, 0) == -1)
      perror("send");
    // TODO link entity and transaction
    for (uint32_t i = 0; i < count; i++) {
      uint32_t entityID;
      if ((numbytes = recv(sockfd, &entityID, sizeof(uint32_t), 0)) == -1) {
        perror("recv");
        exit(1);
      }
      if (send(sockfd, "_", 1, 0) == -1)
        perror("send");
      linkEntityAndTransaction(id, entityID);
    }
    return 0;
  }
  // compare timestamps
  
}

int updateEntity(int sockfd, int numbytes)
{
  uint32_t id;
  if ((numbytes = recv(sockfd, &id, sizeof(uint32_t), 0)) == -1) {
    perror("recv");
    exit(1);
  }
  if (id == 0) {
    //create the entity
  }
}

int normal(int sockfd, int numbytes)
{
  char *pub_key = "public key\0";
  if (send(sockfd, pub_key, 12, 0) == -1)
    perror("send");
  char pub_key_in[500];
  if ((numbytes = recv(sockfd, pub_key_in, 500, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  if (send(sockfd, "_", 1, 0) == -1)
    perror("send");
  char type[4];
  if ((numbytes = recv(sockfd, type, 4, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  printf(type);
  if (type[0] == 'u') {
    //update
    if (type[1] == 't') {
      //transaction
      if (send(sockfd, "_", 1, 0) == -1)
        perror("send");
      updateTransaction(sockfd, numbytes);
    }
    else if (type[1] == 'e') {
      //transaction
      if (send(sockfd, "_", 1, 0) == -1)
        perror("send");
    }
  }
}

int verifyKey(uint32_t id, char *key, char *username, int *usernameLen)
{
  printf("Verify Key\n");
  char *pubKey;
  char *query;
  int size = asprintf(&query, "SELECT * FROM reserve where id='%d';\0", id);
  if (mysql_query(con, query)) {
    fprintf(stderr, "%s\n", mysql_error(con));
    exit(1);
  }
  printf("Selected Key\n");
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned long *lengths;
  unsigned int num_fields;
  unsigned int i;
  res = mysql_use_result(con);
  printf("Got result\n");
  num_fields = mysql_num_fields(res);
  row = mysql_fetch_row(res);
  lengths = mysql_fetch_lengths(res);
  printf("[%.*s]\n", (int) lengths[1], row[1]);
  pubKey = row[1];
  strcpy(username, row[2]);
  *usernameLen = lengths[2];
  printf("server: Key %s\n", pubKey);

  if (!strcmp(pubKey, key)) {
    printf("server: keys don't match");
    return 1;
  }

  mysql_free_result(res);
  return 0;
}

int logIn(int sockfd, int numbytes)
{
  char *pub_key = "public key\0";
  if (send(sockfd, pub_key, 12, 0) == -1)
    perror("send");

  uint32_t id;
  char key[544];
  char username[100];

  if ((numbytes = recv(sockfd, &id, sizeof(uint32_t), 0)) == -1) {
    perror("recv");
    exit(1);
  }
  if (send(sockfd, "_", 1, 0) == -1)
    perror("send");
  printf("server: received id '%d'\n", id);

  // client public key
  if ((numbytes = recv(sockfd, key, 544, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  printf("server: received key '%s'\n", key);
  int usernameLen;
  int result = verifyKey(id, key, username, &usernameLen);
  printf("server: error %d\n", result);
  if (result != 0) {
    printf("server: error with result\n");
    if (send(sockfd, "n", 1, 0) == -1)
      perror("send");
    return 1;
  }
  if (send(sockfd, "y", 1, 0) == -1)
    perror("send");
  char buffer[3];
  if ((numbytes = recv(sockfd, buffer, 1, 0)) == -1) {
    perror("recv");
    exit(1);
  }

  if (send(sockfd, username, usernameLen, 0) == -1)
    perror("send");
  printf("server: sent username '%s'\n", username);
  return 0;
}

int selector(char value, int sockfd, int numbytes)
{
  switch(value) {
  case 'c':
    printf("Creating account\n");
    createAccount(sockfd, numbytes);
    break;
  case 'r':
    break;
  case 'v':
    break;
  case 'n':
    printf("Normal Communication\n");
    normal(sockfd, numbytes);
    break;
  case 'l':
    printf("Logging in\n");
    logIn(sockfd, numbytes);
    break;
  }
  return 0;
}

int main(void)
{
  int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
  char buf[MAXDATASIZE];
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr; // connector's address information
  socklen_t sin_size;
  struct sigaction sa, action;
  int yes=1;
  char s[INET6_ADDRSTRLEN];
  int rv;

  con = mysql_init(NULL);

  if (con == NULL)
  {
    fprintf(stderr, "%s\n", mysql_error(con));
    exit(1);
  }

  if (mysql_real_connect(con, "localhost", "root", "bfKecHhPP8ZRW96QWBUY",
                         "BitAllowance", 0, NULL, 0) == NULL)
  {
    fprintf(stderr, "%s\n", mysql_error(con));
    mysql_close(con);
    exit(1);
  }

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol)) == -1) {
      perror("server: socket");
      continue;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                   sizeof(int)) == -1) {
      perror("setsockopt");
      exit(1);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("server: bind");
      continue;
    }

    break;
  }

  freeaddrinfo(servinfo); // all done with this structure

  if (p == NULL)  {
    fprintf(stderr, "server: failed to bind\n");
    exit(1);
  }

  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  sa.sa_handler = sigchld_handler; // reap all dead processes
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }

  printf("server: waiting for connections...\n");

  while(1) {  // main accept() loop
    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
      perror("accept");
      continue;
    }

    inet_ntop(their_addr.ss_family,
              get_in_addr((struct sockaddr *)&their_addr),
              s, sizeof s);
    printf("server: got connection from %s\n", s);

    if (!fork()) { // this is the child process
      close(sockfd); // child doesn't need the listener

      if ((numbytes = recv(new_fd, buf, 1, 0)) == -1) {
        perror("recv");
        exit(1);
      }

      printf("server: received 1 '%s'\n", buf);

      selector(buf[0], new_fd, numbytes);

      close(new_fd);
      exit(0);
    }
    close(new_fd);  // parent doesn't need this
  }
  mysql_close(con);

  return 0;
}
