
/*
** server.c -- a stream socket server demo
*/

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

//#include <mysql.h>

// the configured options and settings for the server
#define Server_VERSION_MAJOR @Server_VERSION_MAJOR@
#define Server_VERSION_MINOR @Server_VERSION_MINOR@

#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold
#define MAXDATASIZE 100

RSA *r = NULL;
//MYSQL *con;

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

void writeAccount(uint32_t id, char *key, char *username, char *display, char * email)
{
  FILE *fp;
  fp = fopen("data/UserAccount.txt", "w+");
  fprintf(fp, "%d\n", id);
  fputs(key, fp);
  fputs(username, fp);
  fputs("\n", fp);
  fputs(display, fp);
  fputs("\n", fp);
  fputs(email, fp);
  fputs("\n", fp);
  fclose(fp);
  printf("server: wrote to file\n");
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

  writeAccount(1, key, username, display, email);

  uint32_t id = 1;
  uint32_t networkOrderID = htonl(id);
  if (send(sockfd, &networkOrderID, sizeof(uint32_t), 0) == -1)
    perror("send");

  printf("server: sent ID\n");

  return 0;
}

int verifyKey(uint32_t id, char *key, char *username, int *usernameLen)
{
  FILE *fp;
  char *ptr;
  char *line;
  size_t len = 0;
  ssize_t read;
  fp = fopen("data/UserAccount.txt", "r+");
  if (fp == NULL)
    return 0;
  while ((read = getline(&line, &len, fp)) != -1) {
    printf("%u", strtoul(line, &ptr, 10));
    printf("%u", id);
    if (strtoul(line, &ptr, 10) == id)// break when the ID is found in the file
      break;
  }
  if (read == -1)
    return 1;

  char *privKey1;
  char *privKey2;
  read = getline(&privKey1, &len, fp);
  read = getline(&privKey2, &len, fp);
  char *privKey = malloc(strlen(privKey1) + strlen(privKey2) + 2);
  strcpy(privKey, privKey1);
  strcat(privKey, "\n");
  strcat(privKey, privKey2);
  printf("server: Key %s\n", privKey);

  if (!strcmp(privKey, key)) {
    return 1;
  }

  read = getline(&username, &len, fp);
  *usernameLen = read;

  fclose(fp);
  if (line)
    free(line);
  printf("server: read from file\n");
  return 0;
}

int logIn(int sockfd, int numbytes)
{
  char *pub_key = "public key\0";
  if (send(sockfd, pub_key, 12, 0) == -1)
    perror("send");

  uint32_t id;
  char key[544];
  char *username;

  if ((numbytes = recv(sockfd, &id, 4, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  if (send(sockfd, "_", 1, 0) == -1)
    perror("send");

  // client public key
  if ((numbytes = recv(sockfd, key, 544, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  int *usernameLen;
  int result = verifyKey(id, key, username, usernameLen);

  if (result == 1) {
    return 1;
  }

  if (send(sockfd, username, *usernameLen, 0) == -1)
    perror("send");

  printf("server: received key '%s'\n", key);
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

  /*con = mysql_init(NULL);

  if (con == NULL)
  {
    fprintf(stderr, "%s\n", mysql_error(con));
    exit(1);
  }

  if (mysql_real_connect(con, "localhost", "root", "root_pswd",
                         "BitAllowance", 0, NULL, 0) == NULL)
  {
    fprintf(stderr, "%s\n", mysql_error(con));
    mysql_close(con);
    exit(1);
  }

  if (mysql_query(con, "show tables")) {
    fprintf(sterr, "%s\n", mysql_error(con));
    exit(1);
  }

  MYSQL_RES *res;
  MYSQL_ROW row;
  res = mysql_use_result(con);
  printf("MYSQL database:\n");
  while ((row = mysql_fetch_row(res)) != NULL)
    printf("%s \n", row[0]);

  mysql_free_result(res);
  mysql_close(conn);*/

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

  return 0;
}
