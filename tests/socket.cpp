#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include "common.h"

// Reading input from a socket
// In order to run this test in linux, one must run
//     echo hello | nc localhost 12345
// in a terminal twice

TEST_CASE("socket") {
	printf("Socket test\n");

	// Create socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(sockfd > 0);

	// Bind and listen on socket
	struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(12345),
		.sin_addr = { htonl(INADDR_ANY) },
	};
	REQUIRE(bind(sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) == 0);
	REQUIRE(listen(sockfd, 5) == 0);

	// Accept a client
	struct sockaddr_in client_addr;
	uint32_t client_addr_size = sizeof(sockaddr_in);
	int client_fd = accept(sockfd, (sockaddr*)&client_addr, &client_addr_size);
	REQUIRE(client_fd > 0);

	// Read input from sockfd (not connected socket) returns -ENOTCONN
	char buf[6];
	REQUIRE(read_and_check_first_five_bytes(sockfd, buf) == -1);
	REQUIRE(errno == ENOTCONN);

	// Read from client fd
	REQUIRE(read_and_check_first_five_bytes(client_fd, buf) == 0);
	REQUIRE(close(client_fd) == 0);

	// Repeat
	client_fd = accept(sockfd, (sockaddr*)&client_addr, &client_addr_size);
	REQUIRE(client_fd > 0);
	REQUIRE(read_and_check_first_five_bytes(client_fd, buf) == 0);
	REQUIRE(close(client_fd) == 0);

	REQUIRE(close(sockfd) == 0);
}