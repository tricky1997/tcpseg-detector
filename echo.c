#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>

int main(void)
{
	int sockfd;
	int connfd;
	int n;
	const int on = 1;
	char buf[2048];
	struct sockaddr_in addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
		err(1, "socket");

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10000);
	n = bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr));
	if (n == -1)
		err(1, "bind");

	listen(sockfd, 1);
	connfd = accept(sockfd, NULL, NULL);
	if (connfd == -1)
		err(1, "accept");

	while ((n = read(connfd, buf, sizeof(buf))) != 0) {
		if (n == -1)
			err(1, "read");
		buf[n] = 0;
		printf("%s\n", buf);
		n = write(connfd, buf, n);
		if (n == -1)
			err(1, "write");
	}

	close(sockfd);
	close(connfd);
	exit(0);
}
