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

static int tcp_read(int socket, char * buffer, int bufferSize, struct timeval * timeout)
{
	char * tag = "tcp_read";
	int     rc = 0;                     /* return code of select              */
	fd_set  fdvar;                      /* bit array for select call          */
	int     socketerror = 0;
	int     optlen = sizeof(int);
	int     bytesread = 0;

	/*
	* the socket must not be negative
	*/
	if (socket < 0)
	{
		pblCgiExitOnError("%s: Negative socket not allowed!\n", tag);
	}

	/*
	* we clear any error condition on the socket first
	*/
	optlen = sizeof(socketerror);
	getsockopt(socket, SOL_SOCKET, SO_ERROR, (char*)&socketerror, &optlen);

	/*
	* loop until either a timeout or a hard error occurs, or until we
	* we read data
	*/
	while (bytesread < bufferSize)
	{
		/*
		* we use select to see whether there is data available on the
		* socket or to receive a timeout
		*/
		FD_ZERO(&fdvar);                     /* clear the descriptor bitmap */
		FD_SET(socket, &fdvar);             /* only set our socket         */
		errno = 0;

		rc = select(socket + 1,      /* the highest socket to check         */
			&fdvar,           /* check our socket for reading        */
			(fd_set *)0,   /* not interested in write sockets     */
			(fd_set *)0,   /* not interested in OOB sockets       */
			timeout
		);
		switch (rc)
		{
		case 0:
			/*
			* a timeout occurred, set the answer accordingly
			*/
			return (-1);

		case -1:
			/*
			* See whether a real error or an interrupt
			*/
			if (errno == EINTR)
			{
				pblCgiExitOnError("%s: Interrupt!\n", tag);
			}

			/*
			* an error occured during the select
			*/
			pblCgiExitOnError("%s: Select error!\n", tag);

		default:
			/*
			* we clear any error condition on the socket first
			*/
			optlen = sizeof(socketerror);
			if (getsockopt(socket, SOL_SOCKET, SO_ERROR,
				(char *)&socketerror, &optlen))
			{
				pblCgiExitOnError("%s: getsockopt error!\n", tag);
			}

			if (socketerror)
			{
				/*
				* the select most likely only came back because there was
				* an error condition on the socket, therefore we do it
				* again
				*/
				continue;
			}

			/*
			* data is ready to be read at the socket, thus read
			* it byte by byte, we do this in order to be able to
			* see any newlines
			*/
			errno = 0;
			rc = recvfrom(socket, buffer + bytesread, 1, 0, NULL, NULL);
			if (rc < 0)
			{
				/*
				* if we woke up because of a signal
				*/
				if (errno == EINTR)
				{
					pblCgiExitOnError("%s: Interrupt!\n", tag);
				}

				pblCgiExitOnError("%s: Receive error!\n", tag);
			}
			else if (rc == 0)
			{
				/*
				* receiving 0 bytes means the socket has been closed on the
				* other side, just return the number of bytes read so far
				*/
				return(bytesread);
			}

			/*
			* we read a byte,
			*/
			bytesread++;

			if (*(buffer + bytesread - 1) == '\n')
			{
				/*
				* we found a newline, give it up for now
				*/
				return(bytesread);
			}

			/*
			* if there is more space in the buffer
			*/
			if (bytesread < (bufferSize - 1))
			{
				continue;
			}

			/*
			* we got some data, return the length of it
			*/
			return(bytesread);
		}
	}

	pblCgiExitOnError("%s: Interrupt!\n", tag);
	return(-1);

}

/*
* pblCgiHttpGet
*
* Makes a HTTP request with the given uri to the given host/port
* and returns the result content in a malloced buffer.
*/

char * pblCgiHttpGet(char * hostname, int port, char * uri, int timeoutsecs)
{
	struct timeval tvperiod;
	static char * tag = "pblCgiHttpGet";
	int rc = 0;
	int spaceLeft = 0;
	int dataLeft = 0;

	int                 socketFd;
	struct sockaddr_in  serverAddress;
	short               shortPort = 80;

	struct hostent     *hostinfo;

	char               *sendBuffer;
	char               *ptr;
	char                buffer[64 * 1024 + 1];

	tvperiod.tv_sec = timeoutsecs;
	tvperiod.tv_usec = 0;

	if (port)
	{
		shortPort = port;
	}

	hostinfo = gethostbyname(hostname);
	if (!hostinfo)
	{
		pblCgiExitOnError("%s: host \"%s\" is unknown %d.\n", tag, hostname, errno);
	}

	memset((char*)&serverAddress, 0, sizeof(struct sockaddr_in));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(shortPort);
	memcpy(&(serverAddress.sin_addr.s_addr),
		hostinfo->h_addr,
		sizeof(serverAddress.sin_addr.s_addr)
	);

	socketFd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketFd < 0)
	{
		pblCgiExitOnError("%s: Could not open stream socket\n", tag);
	}

	/*
	* now connect to the server
	*/
	if (connect(socketFd, (struct sockaddr *) &serverAddress,
		sizeof(struct sockaddr_in)) < 0)
	{
		pblCgiExitOnError("%s: Error in connect() to host \"%s\" on port %d\n",
			tag, hostname, shortPort);
		socket_close(socketFd);
	}

	/*
	* write the GET request
	*/
	sendBuffer = pblCgiSprintf("GET %s  HTTP/1.0\r\nUser-Agent: DynamicPois\r\n\r\n", uri);
	PBL_CGI_TRACE("HttpRequest=%s", sendBuffer);

	dataLeft = strlen(sendBuffer);
	ptr = sendBuffer;

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
	tvperiod.tv_sec = timeoutsecs;          /* Set timeout values */

	for (;;)
	{
		rc = tcp_read(socketFd, buffer, sizeof(buffer) - 1, &tvperiod);
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
	* check the first line, for HTTP error code
	*  -->  HTTP/1.1 500 Server Error\r\n
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

	if (ptr != NULL)
	{
		/*
		* we have a 200 result code
		* search for the content start
		*/
		ptr = strstr(ptr, "\r\n\r\n");
		if (!ptr)
		{
			ptr = strstr(result, "\n\n");
			if (!ptr)
			{
				pblCgiExitOnError("%s: Bad HTTP response, no separator.\n%s\n", tag, result);
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
	}
	return(ptr);
}

char * getMatchingString(char start, char end, char * string, char **nextPtr)
{
	char * tag = "getMatchingString";
	char * ptr = string;
	if (start != *ptr)
	{
		pblCgiExitOnError("%s: expected %c at start of string %s.\n", tag, start, string);
	}

	int level = 1;
	while (*++ptr)
	{
		if (*ptr == start)
		{
			level++;
		}
		if (*ptr == end)
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

	char * uri = pblCgiSprintf("%s%s HTTP/1.0\r\nUser-Agent: DynamicPois\r\n\r\n",
		baseUri,
		"?lang=EN&countryCode=DE&userId=4ed67bd0624f2f7289961da09ab6217ff2af1456&lon=11.5786916&action=update&version=8.5&radius=146&lat=48.1584706&alt=567&layerName=anthropoceneqcuf&accuracy=100"
	);
	PBL_CGI_TRACE("Uri=%s", uri);

#ifdef _WIN32

	WSADATA wsaData;

	// Initialize Winsock
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0)
	{
		pblCgiExitOnError("%s: WSAStartup failed: %d\n", tag, result);
	}
	PBL_CGI_TRACE("WSAStartup=ok");

#endif

	char * response = pblCgiHttpGet(hostName, port, uri, 16);

	PBL_CGI_TRACE("Response=%s", response);

	char * start = "{\"hotspots\":";
	int length = strlen(start);


	if (strncmp(start, response, length))
	{
		pblCgiExitOnError("%s: Bad response start %s\n", tag, response);
	}

	char * rest = NULL;
	char * hotspotsString = getMatchingString('[', ']', response + length, &rest);

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
		char * hotspot = getMatchingString('{', '}', ptr, &ptr2);

		PBL_CGI_TRACE("hotspot=%s", hotspot);

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