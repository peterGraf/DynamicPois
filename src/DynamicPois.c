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

$Log: DynamicPois.c,v $
Revision 1.5  2018/04/30 16:06:04  peter
Linux port of hit counting

Revision 1.4  2018/04/30 14:22:54  peter
Added hit count handling

Revision 1.3  2018/04/29 20:17:56  peter
Making id of pois unique

Revision 1.2  2018/04/29 20:00:17  peter
Linux port

Revision 1.1  2018/04/29 18:42:08  peter
More work on service

*/

/*
* Make sure "strings <exe> | grep Id | sort -u" shows the source file versions
*/
char * DynamicPois_c_id = "$Id: DynamicPois.c,v 1.5 2018/04/30 16:06:04 peter Exp $";

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
#include <windows.h> 

#define socket_close closesocket

#else

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#define socket_close close

#endif

#include "pblCgi.h"

static int tcpRead(int socket, char * buffer, int bufferSize, struct timeval * timeout)
{
	char * tag = "tcpRead";
	int    rc = 0;

	int socketError = 0;
	int optlen = sizeof(socketError);

	errno = 0;
	if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&socketError, &optlen))
	{
		pblCgiExitOnError("%s: getsockopt(%d) error, errno %d\n", tag, socket, errno);
	}

	int nBytesRead = 0;
	while (nBytesRead < bufferSize)
	{
		fd_set readFds;
		FD_ZERO(&readFds);
		FD_SET(socket, &readFds);

		errno = 0;
		rc = select(socket + 1, &readFds, (fd_set *)NULL, (fd_set *)NULL, timeout);
		switch (rc)
		{
		case 0:
			return (-1);

		case -1:
			if (errno == EINTR)
			{
				pblCgiExitOnError("%s: select(%d) EINTR error, errno %d\n", tag, socket, errno);
			}
			pblCgiExitOnError("%s: select(%d) error, errno %d\n", tag, socket, errno);
			break;

		default:
			errno = 0;
			if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&socketError, &optlen))
			{
				pblCgiExitOnError("%s: getsockopt(%d) error, errno %d\n", tag, socket, errno);
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
					pblCgiExitOnError("%s: recvfrom(%d) EINTR error, errno %d\n", tag, socket, errno);
				}
				pblCgiExitOnError("%s: recvfrom(%d) error, errno %d\n", tag, socket, errno);
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

	errno = 0;
	struct hostent * hostInfo = gethostbyname(hostname);
	if (!hostInfo)
	{
		pblCgiExitOnError("%s: gethostbyname(%s) error, errno %d.\n", tag, hostname, errno);
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

	errno = 0;
	int socketFd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketFd < 0)
	{
		pblCgiExitOnError("%s: socket() error, errno %d\n", tag, errno);
	}

	errno = 0;
	if (connect(socketFd, (struct sockaddr *) &serverAddress, sizeof(struct sockaddr_in)) < 0)
	{
		pblCgiExitOnError("%s: connect(%d) error, host '%s' on port %d, errno %d\n", tag, socketFd, hostname, shortPort, errno);
		socket_close(socketFd);
	}

	char * sendBuffer = pblCgiSprintf("GET %s HTTP/1.0\r\nUser-Agent: DynamicPois\r\n\r\n", uri);
	PBL_CGI_TRACE("HttpRequest=%s", sendBuffer);

	int rc = 0;
	int dataLeft = strlen(sendBuffer);
	char * ptr = sendBuffer;

	while (dataLeft > 0)
	{
		errno = 0;
		rc = send(socketFd, ptr, dataLeft, 0);
		if (rc > 0)
		{
			ptr += rc;
			dataLeft -= rc;
		}
		else
		{
			pblCgiExitOnError("%s: send(%d) error, rc %d, errno %d\n", tag, socketFd, rc, errno);
		}
	}
	PBL_FREE(sendBuffer);

	PblStringBuilder * stringBuilder = pblStringBuilderNew();
	if (!stringBuilder)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}

	struct timeval timeoutValue;
	timeoutValue.tv_sec = timeoutSeconds;
	timeoutValue.tv_usec = 0;

	char buffer[64 * 1024 + 1];
	for (;;)
	{
		rc = tcpRead(socketFd, buffer, sizeof(buffer) - 1, &timeoutValue);
		if (rc < 0)
		{
			pblCgiExitOnError("%s: read failed! rc %d\n", tag, rc);
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
		pblCgiExitOnError("%s: expected %c at start of string '%s'\n", tag, start, string);
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
	pblCgiExitOnError("%s: unexpected end of string in '%s'\n", tag, string);
	return NULL;
}

static char * getStringBetween(char * string, char * start, char * end)
{
	char * tag = "getStringBetween";
	char * ptr = strstr(string, start);
	if (!ptr)
	{
		pblCgiExitOnError("%s: expected starting '%s' in string '%s'\n", tag, start, string);
	}
	ptr += strlen(start);
	char * ptr2 = strstr(ptr, end);
	if (!ptr2)
	{
		pblCgiExitOnError("%s: expected ending '%s' in string '%s'\n", tag, end, ptr);
	}
	return pblCgiStrRangeDup(ptr, ptr2);
}

static void putString(char * string, PblStringBuilder * stringBuilder)
{
	char * tag = "putString";

	if (pblStringBuilderAppendStr(stringBuilder, string) == ((size_t)-1))
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}
	fputs(string, stdout);
}

static int strListElementFree(void * context, int index, void * element)
{
	PBL_FREE(element);
	return 0;
}

static void strListFree(PblList * list)
{
	pblCollectionAggregate(list, NULL, strListElementFree);
	pblListFree(list);
}

static char * getArea()
{
	for (int i = 1; i <= 1000; i++)
	{
		char * areaKey = pblCgiSprintf("Area_%d", i);
		char * areaValue = pblCgiConfigValue(areaKey, NULL);

		if (pblCgiStrIsNullOrWhiteSpace(areaValue))
		{
			PBL_CGI_TRACE("No value for area %s", areaKey);
			PBL_FREE(areaKey);
			return NULL;
		}

		PblList * locationList = pblCgiStrSplitToList(areaValue, ",");
		int size = pblListSize(locationList);
		if (size != 4)
		{
			PBL_CGI_TRACE("%s, expecting 4 location values, current value is %s", areaKey, areaValue);

			strListFree(locationList);
			PBL_FREE(areaKey);
			continue;
		}
		int myLat = (int)(1000000.0 * strtof(pblCgiQueryValue("lat"), NULL));
		int myLon = (int)(1000000.0 * strtof(pblCgiQueryValue("lon"), NULL));

		if (myLat < atoi(pblListGet(locationList, 0)) || myLon < atoi(pblListGet(locationList, 1))
			|| myLat > atoi(pblListGet(locationList, 2)) || myLon > atoi(pblListGet(locationList, 3)))
		{
			PBL_CGI_TRACE("%s, lat %d, lon %d is outside area value %s", areaKey, myLat, myLon, areaValue);

			strListFree(locationList);
			PBL_FREE(areaKey);
			continue;
		}

		PBL_CGI_TRACE("%s, lat %d, lon %d is inside area value %s", areaKey, myLat, myLon, areaValue);

		strListFree(locationList);
		return areaKey;
	}
	return NULL;
}

#ifdef _WIN32

static int isHit(int hitDuration, HANDLE hFind, WIN32_FIND_DATA FindData)
{
	char * timeString = pblCgiStrFromTimeAndFormat(time((time_t*)NULL) - hitDuration, "%02d%02d%02d-%02d%02d%02d");

	SYSTEMTIME stUTC, stLocal;

	// Convert the last-write time to local time.
	FileTimeToSystemTime(&FindData.ftCreationTime, &stUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

	// Build a string showing the date and time.
	char * creationTime = pblCgiSprintf(
		"%02d%02d%02d-%02d%02d%02d",
		stLocal.wYear - 2000, stLocal.wMonth, stLocal.wDay,
		stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

	int rc = strcmp(creationTime, timeString) > 0 ? 1 : 0;

	PBL_FREE(timeString);
	PBL_FREE(creationTime);

	return rc;
}

#endif

static char * areaConfigValue(char * area, char *configKey)
{
	char * key = pblCgiSprintf("%s_%s", area, configKey);
	char * valueString = pblCgiConfigValue(key, "");

	if (pblCgiStrIsNullOrWhiteSpace(valueString))
	{
		valueString = pblCgiConfigValue(configKey, "");
		if (pblCgiStrIsNullOrWhiteSpace(valueString))
		{
			PBL_CGI_TRACE("No value for %s", key);
		}
	}
	PBL_FREE(key);
	return valueString;
}

static int getHitCount(char * area)
{
	char * hitDurationString = areaConfigValue(area, "HitDuration");
	int hitDuration = atoi(hitDurationString);
	if (hitDuration < 1)
	{
		PBL_CGI_TRACE("Bad value for HitDuration %d", hitDuration);
	}
	PBL_CGI_TRACE("HitDuration is %d", hitDuration);

	char * timeString = pblCgiStrFromTimeAndFormat(time((time_t*)NULL), "%02d%02d%02d-%02d%02d%02d");

	char * hitDirectory = pblCgiConfigValue("HitDirectory", "/tmp");
	if (pblCgiStrIsNullOrWhiteSpace(hitDirectory))
	{
		PBL_CGI_TRACE("No value for HitDirectory");
		return 0;
	}
	PBL_CGI_TRACE("HitDirectory %s", hitDirectory);

	char * hitFileName = pblCgiSprintf("%s_%s.txt", area, timeString);
	char * hitFilePath = pblCgiSprintf("%s/%s", hitDirectory, hitFileName);

	PBL_CGI_TRACE("HitFilePath %s", hitFilePath);

	FILE * hitFile = pblCgiFopen(hitFilePath, "a+");
	if (hitFile == NULL)
	{
		PBL_CGI_TRACE("Failed to open hitFile %s", hitFilePath);
		return 0;
	}
	fclose(hitFile);

	int hitCount = 0;

#ifdef _WIN32

	HANDLE hFind;
	WIN32_FIND_DATA FindData;

	// Find the first file

	char * pattern = pblCgiSprintf("%s/%s*.*", hitDirectory, area);
	//pattern = pblCgiStrReplace(pattern, "/", "\\");

	PBL_CGI_TRACE("FindFirstFile %s", pattern);

	size_t size = strlen(pattern) + 1;
	wchar_t* lFilePattern = malloc(sizeof(wchar_t) * size);

	size_t outSize;
	mbstowcs_s(&outSize, lFilePattern, size, pattern, size - 1);
	hFind = FindFirstFile(lFilePattern, &FindData);

	if (INVALID_HANDLE_VALUE == hFind)
	{
		PBL_CGI_TRACE("FindFirstFile failed (%d)\n", GetLastError());
		return 0;
	}

	hitCount += isHit(hitDuration, hFind, FindData);

	while (FindNextFile(hFind, &FindData))
	{
		hitCount += isHit(hitDuration, hFind, FindData);
	}

	FindClose(hFind);

#else

	int length = strlen(area) + 1;
	struct dirent * entry;
	DIR * directory = opendir(hitDirectory);
	if (directory)
	{
	    long firstHitTime = time(NULL) - hitDuration;


		while ((entry = readdir(directory)) != NULL)
		{
			if (strncmp(hitFileName, entry->d_name, length))
			{
				continue;
			}

	        char * directoryFilePath = pblCgiSprintf("%s/%s", hitDirectory, entry->d_name);

	        struct stat st;
	        if (stat(directoryFilePath, &st) != 0)
	        {
	        	PBL_CGI_TRACE("Failed to stat hitFile %s, %d", directoryFilePath, errno);
	        	PBL_FREE(directoryFilePath);
	        	continue;
	        }
	        PBL_FREE(directoryFilePath);

	        if (firstHitTime > st.st_ctim.tv_sec)
	        {
	        	continue;
	        }
			hitCount++;
		}
		closedir(directory);
	}
	else
	{
		PBL_CGI_TRACE("Failed to opendir %s, %d", hitDirectory, errno);
	}

	PBL_FREE(hitFileName);
	PBL_FREE(hitFilePath);
	PBL_FREE(timeString);

#endif

	return hitCount;
}

static int getHitDuplicator(char * area, int hitCount)
{
	char * hitCountLevelsString = areaConfigValue(area, "HitCountLevels");
	char * hitDuplicatorsString = areaConfigValue(area, "HitDuplicators");

	PblList * hitCountLevelsList = pblCgiStrSplitToList(hitCountLevelsString, ",");
	int levelSize = pblListSize(hitCountLevelsList);
	if (levelSize < 1)
	{
		PBL_CGI_TRACE("%s, at least one value for HitCountLevels, value '%s'", area, hitCountLevelsString);

		strListFree(hitCountLevelsList);
		return 0;
	}

	PblList * hitDuplicatorsList = pblCgiStrSplitToList(hitDuplicatorsString, ",");
	int duplicatorSize = pblListSize(hitDuplicatorsList);
	if (duplicatorSize < 1)
	{
		PBL_CGI_TRACE("%s, at least one value for HitDuplicators, value '%s'", area, hitDuplicatorsString);

		strListFree(hitCountLevelsList);
		strListFree(hitDuplicatorsList);
		return 0;
	}

	for (int i = 0; i < levelSize; i++)
	{
		int countLevel = atoi(pblListGet(hitCountLevelsList, i));
		if (hitCount < countLevel)
		{
			int rc = 0;
			if (i < duplicatorSize)
			{
				rc = atoi(pblListGet(hitDuplicatorsList, i));
			}
			else
			{
				rc = atoi(pblListGet(hitDuplicatorsList, duplicatorSize - 1));
			}
			strListFree(hitCountLevelsList);
			strListFree(hitDuplicatorsList);
			return rc;
		}
	}

	int rc = atoi(pblListGet(hitDuplicatorsList, duplicatorSize - 1));
	strListFree(hitCountLevelsList);
	strListFree(hitDuplicatorsList);
	return rc;
}

static char * changeLat(char * string, int i, int difference)
{
	int factor = 1 + (i - 1) / 8;
	int modulo = (i - 1) % 8;

	switch (modulo)
	{
	case 0:
	case 2:
	case 3:
		difference *= factor;
		break;
	case 1:
	case 4:
	case 5:
		difference *= -factor;
		break;
	default:
		return pblCgiStrDup(string);
	}

	char * lat = getStringBetween(string, "\"lat\":", ",");
	PBL_CGI_TRACE("lat=%s", lat);

	char * oldLat = pblCgiSprintf("\"lat\":%s,", lat);
	PBL_CGI_TRACE("oldLat=%s", oldLat);

	char * newLat = pblCgiSprintf("\"lat\":%d,", atoi(lat) + difference);
	PBL_CGI_TRACE("newLat=%s", newLat);

	char * replacedLat = pblCgiStrReplace(string, oldLat, newLat);

	PBL_FREE(lat);
	PBL_FREE(oldLat);
	PBL_FREE(newLat);

	return replacedLat;
}

static char * changeLon(char * string, int i, int difference)
{
	int factor = 1 + (i - 1) / 8;
	int modulo = (i - 1) % 8;

	if (modulo >= 2)
	{
		if (modulo % 2)
		{
			difference *= factor;
		}
		else
		{
			difference *= -factor;
		}
		char * lon = getStringBetween(string, "\"lon\":", ",");
		PBL_CGI_TRACE("lon=%s", lon);

		char * oldLon = pblCgiSprintf("\"lon\":%s,", lon);
		PBL_CGI_TRACE("oldLon=%s", oldLon);

		char * newLon = pblCgiSprintf("\"lon\":%d,", atoi(lon) + difference);
		PBL_CGI_TRACE("newLon=%s", newLon);

		char * replacedLon = pblCgiStrReplace(string, oldLon, newLon);

		PBL_FREE(lon);
		PBL_FREE(oldLon);
		PBL_FREE(newLon);

		return replacedLon;
	}
	return pblCgiStrDup(string);
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

	pblCgiParseQuery(argc, argv);

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

	char * uri = pblCgiSprintf("%s?%s", baseUri, pblCgiQueryString);
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

	char * area = getArea();
	if (area == NULL)
	{
		fputs("Content-Type: application/json\n\n", stdout);
		fputs(response, stdout);
		PBL_CGI_TRACE("Not in any area");
		return(0);
	}

	char * start = "{\"hotspots\":";
	int length = strlen(start);

	if (strncmp(start, response, length))
	{
		fputs("Content-Type: application/json\n\n", stdout);
		fputs(response, stdout);
		PBL_CGI_TRACE("No replacement");
		return(0);
	}

	int numberOfHits = getHitCount(area);
	if (numberOfHits == 0)
	{
		PBL_CGI_TRACE("No hits, no duplication");

		fputs("Content-Type: application/json\n\n", stdout);
		fputs(response, stdout);
		PBL_CGI_TRACE("No replacement");
		return(0);
	}

	int duplicator = getHitDuplicator(area, numberOfHits);
	if (duplicator <= 1)
	{
		PBL_CGI_TRACE("Duplicator value %d, no duplication", duplicator);

		fputs("Content-Type: application/json\n\n", stdout);
		fputs(response, stdout);
		PBL_CGI_TRACE("No replacement");
		return(0);
	}
	PBL_CGI_TRACE("Hits %d, Duplicator %d", numberOfHits, duplicator);

	PblStringBuilder * stringBuilder = pblStringBuilderNew();
	if (!stringBuilder)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
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

	putString("Content-Type: application/json\n\n", stringBuilder);
	putString(start, stringBuilder);
	putString("[", stringBuilder);

	int nPois = pblListSize(list);

	for (int i = 0; i < duplicator; i++)
	{
		int idDifference = i * 1000000;

		for (int j = 0; j < nPois; j++)
		{
			if (i > 0 || j > 0)
			{
				putString(",", stringBuilder);
			}
			putString("{", stringBuilder);

			char * hotspot = pblListGet(list, j);
			if (i == 0)
			{
				putString(hotspot, stringBuilder);
				PBL_CGI_TRACE("hotspot=%s", hotspot);
			}
			else
			{
				char * replacedLat = changeLat(hotspot, i, 100);
				char * replacedLon = changeLon(replacedLat, i, 100);

				char * id = getStringBetween(replacedLon, "\"id\":\"", "\"");
				PBL_CGI_TRACE("id=%s", id);

				char * oldId = pblCgiSprintf("\"id\":\"%s\"", id);
				PBL_CGI_TRACE("oldId=%s", oldId);

				char * newId = pblCgiSprintf("\"id\":\"%d\"", atoi(id) + idDifference);
				PBL_CGI_TRACE("newId=%s", newId);

				char * replacedId = pblCgiStrReplace(replacedLon, oldId, newId);
				PBL_CGI_TRACE("replacedId=%s", replacedId);

				putString(replacedId, stringBuilder);

				PBL_FREE(replacedLat);
				PBL_FREE(replacedLon);

				PBL_FREE(id);
				PBL_FREE(oldId);
				PBL_FREE(newId);
				PBL_FREE(replacedId);
			}
			putString("}", stringBuilder);
		}
	}
	putString("]", stringBuilder);
	putString(rest, stringBuilder);

	PBL_CGI_TRACE("output=%s", pblStringBuilderToString(stringBuilder));
	pblStringBuilderFree(stringBuilder);

	return 0;
}
