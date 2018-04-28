/*
DynamicPois.c - main for dynamic (Common Gateway Interface - CGI) pois service.

Copyright (C) 2018   Tamiko Thiel and Peter Graf

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

For more information on Tamiko Thiel or Peter Graf,
please see: http://www.mission-base.com/.

$Log: CreateAuthor.c,v $
*/

/*
* Make sure "strings <exe> | grep Id | sort -u" shows the source file versions
*/
char * DynamicPois = "$Id: CreateAuthor.c,v 1.1 2018/04/27 16:21:03 peter Exp $";

#include <stdio.h>
#include <memory.h>

#ifndef __APPLE__
#include <malloc.h>
#endif

#include <assert.h>
#include <stdlib.h>

#ifdef _WIN32

#include <winsock2.h>
#include <direct.h>

#else

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#endif

#include "pblCgi.h"
#include "json.h"

#ifdef _WIN32

#define socket_close closesocket

#endif

static int tcpRead(int socket, char * buffer, int bufferSize, struct timeval * timeout)
{
	char * tag = "tcp_read";
	int    rc = 0;
	int    socketError = 0;
	int    optlen = sizeof(int);
	int    nBytesRead = 0;

	errno = 0;
	optlen = sizeof(socketError);
	if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&socketError, &optlen))
	{
		pblCgiExitOnError("%s: getsockopt %d error, errno %d\n", tag, socket, errno);
	}

	while (nBytesRead < bufferSize)
	{
		errno = 0;
		fd_set readFds;
		FD_ZERO(&readFds);
		FD_SET(socket, &readFds);
		
		rc = select(socket + 1, &readFds, (fd_set *)NULL, (fd_set *)NULL, timeout);
		switch (rc)
		{
		case 0:
			return (-1);

		case -1:
			if (errno == EINTR)
			{
				pblCgiExitOnError("%s: select EINTR, errno %d\n", tag, errno);
			}
			pblCgiExitOnError("%s: select error, errno %d\n", tag, errno);

		default:
			optlen = sizeof(socketError);
			if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&socketError, &optlen))
			{
				pblCgiExitOnError("%s: getsockopt error, errno %d\n", tag, errno);
			}

			if (socketError)
			{
				continue;
			}

			errno = 0;
			rc = recvfrom(socket, buffer + nBytesRead, 1, 0, NULL, NULL);
			if (rc < 0)
			{
				if (errno == EINTR)
				{
					pblCgiExitOnError("%s: recvfrom EINTR, errno %d\n", tag, errno);
				}
				pblCgiExitOnError("%s: recvfrom error, errno %d\n", tag, errno);
			}
			else if (rc == 0)
			{
				return(nBytesRead);
			}
			nBytesRead++;
			if (*(buffer + nBytesRead - 1) == '\n')
			{
				return(nBytesRead);
			}

			if (nBytesRead < (bufferSize - 1))
			{
				continue;
			}
			return(nBytesRead);
		}
	}
	return(nBytesRead);
}

/*
* httpGet
*
* Makes a HTTP request with the given uri to the given host/port
* and returns the result content in a malloced buffer.
*/

static char * httpGet(char * hostname, int port, char * uri, int timeoutSeconds)
{
	static char * tag = "httpGet";

	struct hostent * hostInfo = gethostbyname(hostname);
	if (!hostInfo)
	{
		pblCgiExitOnError("%s: host \"%s\" is unknown %d.\n", tag, hostname, errno);
	}

	short shortPort = 80;
	if (port > 0)
	{
		shortPort = port;
	}

	struct sockaddr_in serverAddress;
	memset((char*)&serverAddress, 0, sizeof(struct sockaddr_in));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(shortPort);
	memcpy(&(serverAddress.sin_addr.s_addr), hostInfo->h_addr, sizeof(serverAddress.sin_addr.s_addr));

	int socketFd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketFd < 0)
	{
		pblCgiExitOnError("%s: Could not open stream socket\n", tag);
	}

	if (connect(socketFd, (struct sockaddr *) &serverAddress, sizeof(struct sockaddr_in)) < 0)
	{
		pblCgiExitOnError("%s: Error in connect() to host \"%s\" on port %d\n",
			tag, hostname, shortPort);
		socket_close(socketFd);
	}

	/*
	* write the GET request
	*/
	char * sendBuffer = pblCgiSprintf("GET %s HTTP/1.0\r\nUser-Agent: DynamicPois\r\n\r\n", uri);
	PBL_CGI_TRACE("HttpRequest=%s", sendBuffer);

	int rc = 0;
	int dataLeft = strlen(sendBuffer);
	char * ptr = sendBuffer;

	while (dataLeft > 0)
	{
		rc = send(socketFd, ptr, dataLeft, 0);
		if (rc > 0)
		{
			ptr += rc;
			dataLeft -= rc;
		}
		else
		{
			pblCgiExitOnError("%s: send failed! rc %s\n", tag, rc);
		}
	}
	PBL_FREE(sendBuffer);

	PblStringBuilder * stringBuilder = pblStringBuilderNew();
	if (!stringBuilder)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}

	/*
	* read the response
	*/
	struct timeval timeoutValue;
	timeoutValue.tv_sec = timeoutSeconds;
	timeoutValue.tv_usec = 0;

	char buffer[64 * 1024 + 1];
	for (;;)
	{
		rc = tcpRead(socketFd, buffer, sizeof(buffer) - 1, &timeoutValue);
		if (rc < 0)
		{
			pblCgiExitOnError("%s: read failed! rc %s\n", tag, rc);
		}
		else if (rc == 0)
		{
			break;
		}
		buffer[rc] = '\0';
		if (pblStringBuilderAppendStr(stringBuilder, buffer) == ((size_t)-1))
		{
			pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
		}
	}
	socket_close(socketFd);

	char * result = pblStringBuilderToString(stringBuilder);
	if (!result)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}
	pblStringBuilderFree(stringBuilder);

	/*
	* check for HTTP error code like HTTP/1.1 500 Server Error
	*/
	ptr = strstr(result, "HTTP/");
	if (ptr)
	{
		ptr = strstr(ptr, " ");
		if (ptr)
		{
			ptr++;
			if (strncmp(ptr, "200", 3))
			{
				pblCgiExitOnError("%s: Bad HTTP response\n%s\n", tag, result);
			}
		}
	}

	if (!ptr)
	{
		pblCgiExitOnError("%s: Expecting HTTP response\n%s\n", tag, result);
	}

	ptr = strstr(ptr, "\r\n\r\n");
	if (!ptr)
	{
		ptr = strstr(result, "\n\n");
		if (!ptr)
		{
			pblCgiExitOnError("%s: Illegal HTTP response, no separator.\n%s\n", tag, result);
		}
		else
		{
			ptr += 2;
		}
	}
	else
	{
		ptr += 4;
	}
	return(ptr);
}

static char * getMatchingString(char * string, char start, char end, char **nextPtr)
{
	char * tag = "getMatchingString";
	char * ptr = string;
	if (start != *ptr)
	{
		pblCgiExitOnError("%s: expected %c at start of string %s.\n", tag, start, string);
	}

	int level = 1;
	int c;
	while ((c = *++ptr))
	{
		if (c == start)
		{
			level++;
		}
		if (c == end)
		{
			level--;
			if (level < 1)
			{
				if (nextPtr)
				{
					*nextPtr = ptr + 1;
				}
				return pblCgiStrRangeDup(string + 1, ptr);
			}
		}
	}
	pblCgiExitOnError("%s: unexpected end of string in %s.\n", tag, string);
	return NULL;
}

static char * getStringBetween(char * string, char * start, char * end)
{
	char * tag = "getStringBetween";
	char * ptr = strstr(string, start);
	if (!ptr)
	{
		pblCgiExitOnError("%s: expected %s in string %s.\n", tag, start, string);
	}

	char * ptr2 = strstr(ptr, end);
	if (!ptr2)
	{
		pblCgiExitOnError("%s: expected %s in string %s.\n", tag, end, ptr);
	}
	return pblCgiStrRangeDup(ptr + strlen(start), ptr2);
}

static char * replaceStringAtLeastOnce(char * string, char * oldValue, char * newValue)
{
	char * tag = "replaceStringAtLeastOnce";
	char * ptr = string;
	char * ptr2 = strstr(string, oldValue);
	if (!ptr2)
	{
		pblCgiExitOnError("%s: expected %s at least once in string %s.\n", tag, oldValue, string);
	}
	int length = strlen(oldValue);

	PblStringBuilder * stringBuilder = pblStringBuilderNew();
	if (!stringBuilder)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}

	for (;;)
	{
		if (ptr2 > ptr)
		{
			if (pblStringBuilderAppendStrN(stringBuilder, ptr2 - ptr, ptr) == ((size_t)-1))
			{
				pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
			}
		}
		ptr += (ptr2 - ptr) + length;

		if (pblStringBuilderAppendStr(stringBuilder, newValue) == ((size_t)-1))
		{
			pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
		}

		ptr2 = strstr(ptr, oldValue);
		if (!ptr2)
		{
			if (pblStringBuilderAppendStr(stringBuilder, ptr) == ((size_t)-1))
			{
				pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
			}
			break;
		}
	}

	char * result = pblStringBuilderToString(stringBuilder);
	if (!result)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}
	pblStringBuilderFree(stringBuilder);
	return result;
}

// Main
//
int main(int argc, char * argv[])
{
	char * tag = "DynamicPois";

	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	pblCgiConfigMap = pblCgiFileToMap(NULL, "../config/poisconfig.txt");

	char * traceFile = pblCgiConfigValue(PBL_CGI_TRACE_FILE, "");
	pblCgiInitTrace(&startTime, traceFile);

	char * hostName = pblCgiConfigValue("HostName", "www.mission-base.de");
	if (pblCgiStrIsNullOrWhiteSpace(hostName))
	{
		pblCgiExitOnError("%s: HostName must be given.\n", tag);
	}
	PBL_CGI_TRACE("HostName=%s", hostName);

	int port = 80;
	char * portString = pblCgiConfigValue("Port", "80");
	if (!pblCgiStrIsNullOrWhiteSpace(portString))
	{
		PBL_CGI_TRACE("Port=%s", portString);
		int givenPort = atoi(portString);
		if (givenPort < 1)
		{
			pblCgiExitOnError("%s: Bad port %d.\n", tag, givenPort);
		}
		port = givenPort;
	}

	char * baseUri = pblCgiConfigValue("BaseUri", "/porpoise/web/porpoise.php");
	if (pblCgiStrIsNullOrWhiteSpace(baseUri))
	{
		pblCgiExitOnError("%s: BaseUri must be given.\n", tag);
	}
	PBL_CGI_TRACE("BaseUri=%s", baseUri);

	char * uri = pblCgiSprintf("%s%s",
		baseUri,
		"?lang=EN&countryCode=DE&userId=4ed67bd0624f2f7289961da09ab6217ff2af1456&lon=11.5787019&action=refresh&version=8.5"
		"&radius=1673&lat=48.1584722&alt=567&layerName=anthropoceneqcuf&accuracy=100"
	);
	PBL_CGI_TRACE("Uri=%s", uri);

#ifdef _WIN32

	// Initialize Winsock
	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0)
	{
		pblCgiExitOnError("%s: WSAStartup failed: %d\n", tag, result);
	}
	PBL_CGI_TRACE("WSAStartup=ok");

#endif

	char * response = httpGet(hostName, port, uri, 16);

	PBL_CGI_TRACE("Response=%s", response);

	char * start = "{\"hotspots\":";
	int length = strlen(start);

	if (strncmp(start, response, length))
	{
		pblCgiExitOnError("%s: Bad response start %s\n", tag, response);
	}

	char * rest = NULL;
	char * hotspotsString = getMatchingString(response + length, '[', ']', &rest);

	PBL_CGI_TRACE("hotspotsString=%s", hotspotsString);
	PBL_CGI_TRACE("rest=%s", rest);

	PblList * list = pblListNewArrayList();
	if (!list)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}

	char * ptr = hotspotsString;
	while (*ptr == '{')
	{
		char * ptr2 = NULL;
		char * hotspot = getMatchingString(ptr, '{', '}', &ptr2);

		PBL_CGI_TRACE("hotspot=%s", hotspot);

		char * lat = getStringBetween(hotspot, "\"lat\":", ",");
		PBL_CGI_TRACE("lat=%s", lat);

		char * replaced = replaceStringAtLeastOnce(hotspot, "{", "|");
		PBL_CGI_TRACE("replaced=%s", replaced);

		char * lon = getStringBetween(hotspot, "\"lon\":", ",");
		PBL_CGI_TRACE("lon=%s", lon);

		if (pblListAdd(list, hotspot) < 0)
		{
			pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
		}
		if (*ptr2 != ',')
		{
			break;
		}
		ptr = ptr2 + 1;
	}


	return 0;
}