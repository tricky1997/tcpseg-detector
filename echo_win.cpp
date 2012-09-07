#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>


#define DEFAULT_PORT	10000
#define BUFFER_SIZE		4096
#define DEFAULT_ADDR_LEN 128
#define MAX_CLIENT (FD_SETSIZE -1)
int nPort	= DEFAULT_PORT;
char szAddr[DEFAULT_ADDR_LEN];
char szBuffer[BUFFER_SIZE];
BOOL bInterface = FALSE;
BOOL bEchoBack	= FALSE;

void usage(void);
void checkArgv(int argc, char **argv);
BOOL insertSocket(SOCKET *pClient, SOCKET s);

int main(int argc, char *argv[])
{
	WSAData wsaData;
	WORD wVersion = MAKEWORD(2,2);
	SOCKET s, sClient;
	SOCKADDR_IN sa, saRemote;
	int nRet, nLen, i, nLeft, idx, nRecvLen;
	SOCKET arrClientSocket[MAX_CLIENT] = {INVALID_SOCKET};

	checkArgv(argc, argv);
	nRet = WSAStartup(wVersion, &wsaData);

	if (SOCKET_ERROR == nRet)
	{
		printf("\nWindows socket startup error:%d\n", WSAGetLastError());
		return 1;
	}

	printf("Socket initalization.....\n");
	
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (INVALID_SOCKET == s)
	{
		printf("\nScoket was created error:%d\n", WSAGetLastError());
		return 1;
	}

	printf("socket was created\n");

	nLen = sizeof(SOCKADDR_IN);
	memset(&sa, 0, nLen);
	sa.sin_family = AF_INET;
	sa.sin_port	  = htons(nPort);

	if (bInterface)
	{
		sa.sin_addr.s_addr = inet_addr(szAddr);
	}
	else
	{
		sa.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	nRet = bind(s, (LPSOCKADDR)&sa, nLen);
	if (SOCKET_ERROR == nRet)
	{
		printf("Socket bind error:%d\n", WSAGetLastError());
		return 1;
	}

	printf("bind was successed\n");

	nRet = listen(s, 8);
	if (SOCKET_ERROR == nRet)
	{
		printf("Socket listen error:%d\n", WSAGetLastError());
		return 1;
	}
	
	printf("listen was successed\n");

	fd_set fdRead;
	for(i = 0;i < MAX_CLIENT; i++)
	{
		arrClientSocket[i] = INVALID_SOCKET;
	}

	for(;;)
	{
		FD_ZERO(&fdRead);
		FD_SET(s, &fdRead);
		for(i = 0; i < MAX_CLIENT; i++)
		{
			if (INVALID_SOCKET != arrClientSocket[i])
			{
				FD_SET(arrClientSocket[i], &fdRead);
			}
		}

		nRet = select(0, &fdRead, NULL, NULL, NULL);
		if (SOCKET_ERROR == nRet)
		{
			printf("\nSelect() error:%d\n", WSAGetLastError());
			break;
		}

		if (nRet > 0)
		{
			if(FD_ISSET(s, &fdRead))
			{
				sClient = accept(s, (LPSOCKADDR)&saRemote, &nLen);
				insertSocket(arrClientSocket, sClient);
				printf("Sokcet:%d, was accept()\n", sClient);
				continue;
			}
			for(i = 0; i < MAX_CLIENT; i++)
			{
				if (FD_ISSET(arrClientSocket[i], &fdRead))
				{
					memset(szBuffer, 0, BUFFER_SIZE);
					nRet = recv(arrClientSocket[i], szBuffer, BUFFER_SIZE, 0);
					if (nRet <= 0)
					{
						closesocket(arrClientSocket[i]);
						arrClientSocket[i] = INVALID_SOCKET;
						continue;
					}

					nRecvLen = nRet;
					printf("Socket:%d, %d, send data:%s\n", arrClientSocket[i], nRet, szBuffer);
					

					if (!bEchoBack)
					{
						nRet = getpeername(arrClientSocket[i], (LPSOCKADDR)&saRemote, &nLen);
						if (SOCKET_ERROR == nRet)
						{
							printf("\ngetpeername() error:%d\n", WSAGetLastError());
							continue;
						}
						nLeft = nRecvLen;
						idx = 0;
						while (nLeft > 0)
						{
							nRet = send(arrClientSocket[i], &szBuffer[idx], nLeft, 0);
							if (0 == nRet) 
								break;
							else if (SOCKET_ERROR == nRet)
							{
								printf("Send() failed:%d\n", WSAGetLastError());
								break;
							}
							nLeft -= nRet;
							idx += nRet;
						}
					}
				}
			}
		}
	}
	closesocket(s);
	WSACleanup();
	return 0;
}

void usage(void)
{
	printf("usage: selectecho.exe [-p:5566] [-i:127.0.0.1] [-o]\n\n");
	printf("/t-p:监听的端口号， 在1024到65535之间\n");
	printf("/t-i:监听的服务器地址\n");
	printf("/t-o:是否将数据发回客户端\n\n");
	ExitProcess(1);
}

void checkArgv(int argc, char **argv)
{
	int i;
	for(i = 1; i < argc; i++)
	{
		if(('/' == argv[i][0]) || ('-' == argv[i][1]))
		{
			switch(tolower(argv[i][1]))
			{
				case 'p':
					nPort = atoi(&argv[i][3]);
					break;
				case 'i':
					memset(szAddr, 0, DEFAULT_ADDR_LEN);
					strcpy(szAddr, &argv[i][3]);
					bInterface = TRUE;
					break;
				case 'o':
					bEchoBack = TRUE;
					break;
				default:
					usage();
					break;
			}
		}
	}
}

BOOL insertSocket(SOCKET *pClient, SOCKET s)
{
	int i;
	BOOL bResult = FALSE;
	for(i = 0; i < MAX_CLIENT; i++)
	{
		if (INVALID_SOCKET == pClient[i])
		{
			pClient[i] = s;
			bResult = TRUE;
			break;
		}
	}
	return bResult;
}
