#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<pthread.h>
#include<sys/stat.h>
#include<time.h>
#include<crypt.h>
#include<shadow.h>
#include<sqlite3.h>
#define PORTNUM 1234
#define MAX_CLIENT 1024
#define BUF_SIZE 512

typedef struct socket_info {
	int sd, socket_addr_size;
	struct sockaddr_in socket_addr;
}SOCKET;
typedef struct recv_data {
	char syscommand[32];
	char date[11];
	char time1[6];
	char time2[6];

	char id[9];
	char pw[33];
}RECV_DATA;

int keycmp(char *, int, int);
void itoa(int, char *, int);
int main(void) {
	FILE *stream;
	int pid, rc, i, j;
	char buf[BUF_SIZE], sql[128];
	SOCKET client[2], server;
	client[1].sd = 0;
	// serial-key activation
	/*
	if(!(stream = fopen("serial-key.txt", "r"))) return 0;
	fgets(buf, BUF_SIZE, stream);
	if(strlen(buf) > 128) return 0;
	if(!keycmp(buf, 3, 0)) return 0;*/
	printf("Activation Success!\n");

	memset(&server.socket_addr, 0, sizeof(server.socket_addr));
	server.socket_addr.sin_family = AF_INET;
	server.socket_addr.sin_port = htons(PORTNUM);
	server.socket_addr.sin_addr.s_addr  = htonl(INADDR_ANY);

	int rn, sendbuf_size, recvbuf_size;
	rn = sizeof(int);

	if((server.sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			exit(1);
	}

	int val = 1;
	if (setsockopt(server.sd, SOL_SOCKET, SO_REUSEADDR, (char *) &val, sizeof(int)) < 0) {
		perror("setsockopt SO_REUSEADDR");
		close(server.sd);
		return 1;
	}

	if (setsockopt(server.sd, IPPROTO_TCP, TCP_NODELAY, (char *) &val, sizeof(int)) < 0) {
		perror("setsockopt TCP_NODELAY");
		close(server.sd);
		return 1;
	}

	getsockopt(server.sd, SOL_SOCKET, SO_SNDBUF, &sendbuf_size, (socklen_t *)&rn);
	if(sendbuf_size < 512)
	{
		sendbuf_size = 512;
		setsockopt(server.sd, SOL_SOCKET, SO_SNDBUF, &sendbuf_size,  sizeof(int));
	}
	getsockopt(server.sd, SOL_SOCKET, SO_RCVBUF, &recvbuf_size, (socklen_t *)&rn);
	if(recvbuf_size < 512)
	{
		recvbuf_size = 512;
		setsockopt(server.sd, SOL_SOCKET, SO_RCVBUF, &recvbuf_size,  sizeof(int));
	}

	struct linger linger_val;
	linger_val.l_onoff = 1;
	linger_val.l_linger = 5;
	setsockopt(server.sd, SOL_SOCKET, SO_LINGER, &linger_val,  sizeof(linger_val));

	if(bind(server.sd, (struct sockaddr *)&server.socket_addr, sizeof(server.socket_addr))) {
		perror("bind");
		exit(1);
	}
	if(listen(server.sd, 128)) {
		perror("listen");
		exit(1);
	}
	printf("TCP Server now ready.\n");
	printf("Now Listening...\n");

	while(1)
	{
		client[0].socket_addr_size = sizeof(client[0].socket_addr);
		if((client[0].sd = accept(server.sd, (struct sockaddr *)&client[0].socket_addr, &client[0].socket_addr_size)) == -1) {
			perror("accept");
			continue;
		}
		if(client[1].sd > 0)
		{
			shutdown(client[1].sd, SHUT_RDWR);
			close(client[1].sd);
		}
		client[1].sd = client[0].sd;
		// a connection has been established
		pid = fork();

		// check if the process ID is zero
		if (pid < 0)
		{
			perror("UDP Server: ERROR while forking new process.\n");
			continue;
		}
		else if (pid == 0)
		{
			// we are now inside the new forked process
			printf("We are now inside the new forked process : client(%s)\n", inet_ntoa(client[0].socket_addr.sin_addr));
			char recvbuf[BUF_SIZE];
			char *s;
			FILE *stream;
			RECV_DATA data;
			sqlite3 *db;
			sqlite3_stmt *stmt;

			int recv_size = recv(client[0].sd, recvbuf, sizeof(recvbuf), 0);
			recvbuf[recv_size] = '\0';
//			printf("received %dbytes : %s\n", recv_size, recvbuf);




			// recv-buf error handling
			// syscommand token
			if((s = strtok(recvbuf, ";")) == NULL)
			{
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(1);
			}
			if(strlen(s) > 31)
			{
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(1);
			}

			//for Auth step
			if(!strcmp(s, "auth"))
			{
				if((s = strtok(NULL, ";")) == NULL)
				{
					shutdown(client[0].sd, SHUT_RDWR);
					close(client[0].sd);
					close(server.sd);
					exit(1);
				}
				if(strlen(s) > 8)
				{
					shutdown(client[0].sd, SHUT_RDWR);
					close(client[0].sd);
					close(server.sd);
					exit(1);
				}
				strcpy(data.id, s);
				if((s = strtok(NULL, ";")) == NULL)
				{
					shutdown(client[0].sd, SHUT_RDWR);
					close(client[0].sd);
					close(server.sd);
					exit(1);
				}
				if(strlen(s) > 32)
				{
					shutdown(client[0].sd, SHUT_RDWR);
					close(client[0].sd);
					close(server.sd);
					exit(1);
				}
				strcpy(data.pw, s);

				struct spwd *sp;
				sp = getspnam(data.id);
				if(!strcmp(crypt(data.pw, sp->sp_pwdp), sp->sp_pwdp))
				{
					char ch[120];
					gen(ch, 3, 0);
					strcpy(buf, ch);
					if(send(client[0].sd, buf, strlen(buf), 0) == -1) {
						perror("send 1");
					}
				}
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(0);
			}
			strcpy(data.syscommand, s);

			// date token
			if((s = strtok(NULL, ";")) == NULL)
			{
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(1);
			}
			if(strlen(s) > 14)
			{
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(1);
			}
			strcpy(data.date, s);

			// time1 token
			if((s = strtok(NULL, ";")) == NULL)
			{
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(1);
			}
			if(strlen(s) > 5)
			{
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(1);
			}
			strcpy(data.time1, s);

			// time2 token
			if((s = strtok(NULL, ";")) == NULL)
			{
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(1);
			}
			if(strlen(s) > 5)
			{
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				exit(1);
			}
			strcpy(data.time2, s);

			// db open
			rc = sqlite3_open_v2("db", &db, SQLITE_OPEN_READWRITE, NULL);
			if(rc != SQLITE_OK)
			{
				fprintf(stderr, "db init error.\n");
				return 1;
			}
//			fprintf(stderr, "db init.\n");

			// send process
			strcpy(sql, "SELECT * FROM TB_VAL WHERE TM >= datetime(?) AND TM <= datetime(?) AND COMM = ?;");
			rc = sqlite3_prepare_v2(db, sql, sizeof(sql), &stmt, NULL);
			if(rc != SQLITE_OK)
			{
				printf("errcode : %d!\n", rc);
				shutdown(client[0].sd, SHUT_RDWR);
				close(client[0].sd);
				close(server.sd);
				return 1;
			}
			printf("no errcode\n");
//			fprintf(stderr, "(%s, %d) (%s, %d)\n", data.date, sizeof(data.date), data.syscommand, sizeof(data.syscommand));

			char str[16], str1[17], str2[17];
			snprintf(str1, 17, "%s %s", data.date, data.time1);
			sqlite3_bind_text(stmt, 1, str1, -1, NULL);
//			printf("st: %s\n", str1);
			snprintf(str2, 17, "%s %s", data.date, data.time2);
			sqlite3_bind_text(stmt, 2, str2, -1, NULL);
//			printf("ed: %s\n", str2);
			sqlite3_bind_text(stmt, 3, data.syscommand, -1, NULL);

			char da[11] = {0}, ti[6] = {0};
			for(i = 0; i < 24; i++)
			{
				buf[0] = '\0';
				for(j = 0; j < 60; j++)
				{
					if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
					{
						i = 25;
						break;
					}
					else if(rc != SQLITE_ROW)
					{
						printf("errcode : %d!\n", rc);
						continue;
					}
					s = sqlite3_column_text(stmt, 1);
					if(i == 0 && j == 0)
					{
						strncpy(da, s, 10);
						da[10] = '\0';
						strcat(buf, "DA");
						strcat(buf, da);
						strcat(buf, ";");
					}
					strncpy(ti, &s[11], 5);
					ti[5] = '\0';

//					printf("%s/%s\n", da, ti);
					strcat(buf, "TI");
					strcat(buf, ti);
					strcat(buf, ";");
					itoa(sqlite3_column_int(stmt, 3), str, sizeof(str)); // HA
					strcat(buf, "HA");
					strcat(buf, str);
					strcat(buf, ".");
//					printf("HA: %s", str);
					itoa(sqlite3_column_int(stmt, 4), str, sizeof(str)); // HS
					strcat(buf, "HS");
					strcat(buf, str);
					strcat(buf, ".");
//					printf("HS: %s", str);
					strcat(buf, "VA");
					strcat(buf, sqlite3_column_text(stmt, 5));
					strcat(buf, ";");
//					printf("VA\n");
				}
//				printf("send: %s", buf);
				if(strlen(buf) == 0) break;
				if(send(client[0].sd, buf, strlen(buf), 0) == -1)
					perror("send 1");
			}
			sqlite3_finalize(stmt);
			sqlite3_close_v2(db);
//			printf("send finish!\n");
			shutdown(client[0].sd, SHUT_RDWR);
			close(client[0].sd);
			close(server.sd);
			return 0;
		}
	}
	return 0;
}
int keycmp(char *str, int x, int d)
{
	int i, s[100], cnt = 0;

	for(i = 0; i < 128; i++)
	{
		if(*(str + i) == NULL) break;
		if(*(str + i) == '-') continue;
		s[cnt++] = *(str + i) - '0';
	}
	if(cnt != 100) return 0;
	for(i = 0; i < cnt - 2; i++)
	{
		d = (3 * x) ^ s[i];
		x = x + d;
	}
	x = x % 100;
	if(x == s[cnt - 2] * 10 + s[cnt - 1])
		return 1;
	return 0;
}
void gen(char *ch, int x, int d)
{
	int i, s[99];

	for(i = 0; i < 99; i++)
		s[i] = rand() % 10;
	for(i = 0; i < 99; i++)
	{
		d = (3 * x) ^ s[i];
		x = x + d;
	}
	x = x % 100;
	int j = 0;
	for(i = 0; i < 98; i++)
	{
		if(i == 0)
			sprintf(ch + i + j, "%d", s[i]);
		else if(i % 5 == 0)
		{
			sprintf(ch + i + j, "-%d", s[i]);
			j++;
		}
		else
			sprintf(ch + i + j, "%d", s[i]);
	}
	sprintf(ch + 117, "%d", x);
}
void itoa(int val, char *des, int size){
//    if(val < 10)
//   		snprintf(des, size + 1, "0%d", val);
//    else
	snprintf(des, size + 1, "%d", val);
}

