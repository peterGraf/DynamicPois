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
Revision 1.13  2018/05/25 20:03:08  peter
Produce a hit only if action=refresh

Revision 1.12  2018/05/13 19:29:09  peter
Added cookie handling

Revision 1.11  2018/05/13 15:47:08  peter
More symmetrical position change

Revision 1.10  2018/05/02 21:56:01  peter
Improved lat, lon handling after code review

Revision 1.9  2018/05/01 12:19:09  peter
Cleanup after Linux port

Revision 1.8  2018/05/01 11:46:36  peter
Added relativeAlt handling

Revision 1.7  2018/05/01 00:03:43  peter
Cleanup

Revision 1.6  2018/04/30 22:29:20  peter
Improved ht count

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
char * DynamicPois_c_id = "$Id: DynamicPois.c,v 1.13 2018/05/25 20:03:08 peter Exp $";

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

#ifndef h_addr
#define h_addr h_addr_list[0] /* for backward compatibility */
#endif

#endif

#include "pblCgi.h"

/*
 * Receive some bytes from a socket
 */
static int receiveBytesFromTcp(int socket, char * buffer, int bufferSize, struct timeval * timeout)
{
	char * tag = "readTcp";
	int    rc = 0;
	int    socketError = 0;
	int    optlen = sizeof(socketError);

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
			rc = recvfrom(socket, buffer + nBytesRead, bufferSize - nBytesRead, 0, NULL, NULL);
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
				return nBytesRead;
			}
			nBytesRead += rc;
		}
	}
	return nBytesRead;
}

/*
* Receive some string bytes and return the result in a malloced buffer.
*/
static char * receiveStringFromTcp(int socket, int timeoutSeconds)
{
	static char * tag = "receiveStringFromTcp";

	char * result = NULL;
	PblStringBuilder * stringBuilder = NULL;
	
	struct timeval timeoutValue;
	timeoutValue.tv_sec = timeoutSeconds;
	timeoutValue.tv_usec = 0;

	char buffer[64 * 1024];
	buffer[0] = '\0';

	for (;;)
	{
		int rc = receiveBytesFromTcp(socket, buffer, sizeof(buffer) - 1, &timeoutValue);
		if (rc < 0)
		{
			pblCgiExitOnError("%s: readTcp failed! rc %d\n", tag, rc);
		}
		else if (rc == 0)
		{
			break;
		}
		buffer[rc] = '\0';

		if (rc < sizeof(buffer) - 1 && stringBuilder == NULL)
		{
			result = pblCgiStrDup(buffer);
			break;
		}

		if (stringBuilder == NULL)
		{
			PblStringBuilder * stringBuilder = pblStringBuilderNew();
			if (!stringBuilder)
			{
				pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
			}
		}
		if (pblStringBuilderAppendStr(stringBuilder, buffer) == ((size_t)-1))
		{
			pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
		}
	}

	if (result == NULL)
	{
		if (stringBuilder == NULL)
		{
			pblCgiExitOnError("%s: socket %d received 0 bytes as response\n", tag, socket);
		}

		char * result = pblStringBuilderToString(stringBuilder);
		if (!result)
		{
			pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
		}
	}
	if (stringBuilder)
	{
		pblStringBuilderFree(stringBuilder);
	}
	return result;
}

/*
* Send some bytes to a tcp socket
*/
static void sendBytesToTcp(int socket, char * buffer, int nBytesToSend)
{
	static char * tag = "sendBytesToTcp";

	char * ptr = buffer;
	while (nBytesToSend > 0)
	{
		errno = 0;
		int rc = send(socket, ptr, nBytesToSend, 0);
		if (rc > 0)
		{
			ptr += rc;
			nBytesToSend -= rc;
		}
		else
		{
			pblCgiExitOnError("%s: send(%d) error, rc %d, errno %d\n", tag, socket, rc, errno);
		}
	}
}

/*
* Connect ot a tcp socket on machine with hostname and port
*/
static int connectToTcp(char * hostname, int port)
{
	static char * tag = "getHttpResponse";

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
	return socketFd;
}

/*
* Make a HTTP request with the given uri to the given host/port
* and return the result content in a malloced buffer.
*/
static char * getHttpResponse(char * hostname, int port, char * uri, int timeoutSeconds)
{
	static char * tag = "getHttpResponse";

	int socketFd = connectToTcp(hostname, port);

	char * sendBuffer = pblCgiSprintf("GET %s HTTP/1.0\r\nUser-Agent: DynamicPois\r\n\r\n", uri);
	PBL_CGI_TRACE("HttpRequest=%s", sendBuffer);

	sendBytesToTcp(socketFd, sendBuffer, strlen(sendBuffer));
	PBL_FREE(sendBuffer);

	char * response = receiveStringFromTcp(socketFd, timeoutSeconds);
	PBL_CGI_TRACE("HttpResponse=%s", response);
	socket_close(socketFd);

	return response;
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

static char * getNumberString(char * string, char * start)
{
	char * tag = "getNumberString";
	char * ptr = strstr(string, start);
	if (!ptr)
	{
		pblCgiExitOnError("%s: expected starting '%s' in string '%s'\n", tag, start, string);
	}
	ptr += strlen(start);

	char * ptr2 = ptr;
	while (*ptr2)
	{
		if (isdigit(*ptr2) || '.' == *ptr2 || '-' == *ptr2 || '+' == *ptr2)
		{
			ptr2++;
			continue;
		}
		break;
	}
	if (!ptr2)
	{
		pblCgiExitOnError("%s: expected number ending in string '%s'\n", tag, ptr);
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

static void freeStringList(PblList * list)
{
	while (!pblListIsEmpty(list))
	{
		free(pblListPop(list));
	}
	pblListFree(list);
}

static char * getArea(int lat, int lon)
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

			freeStringList(locationList);
			PBL_FREE(areaKey);
			continue;
		}

		if (lat < atoi(pblListGet(locationList, 0)) || lon < atoi(pblListGet(locationList, 1))
			|| lat > atoi(pblListGet(locationList, 2)) || lon > atoi(pblListGet(locationList, 3)))
		{
			PBL_CGI_TRACE("%s, lat %d, lon %d is outside area value %s", areaKey, lat, lon, areaValue);

			freeStringList(locationList);
			PBL_FREE(areaKey);
			continue;
		}
		PBL_CGI_TRACE("%s, lat %d, lon %d is inside area value %s", areaKey, lat, lon, areaValue);

		freeStringList(locationList);
		return areaKey;
	}
	return NULL;
}

static char * getAreaConfigValue(char * area, char *configKey)
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

static char * timeStringFormat = "%02d%02d%02d-%02d%02d%02d";

static int getHitCount(char * area)
{
	char * hitDurationString = getAreaConfigValue(area, "HitDuration");
	int hitDuration = atoi(hitDurationString);
	if (hitDuration < 1)
	{
		PBL_CGI_TRACE("Bad value for HitDuration %d", hitDuration);
	}
	//PBL_CGI_TRACE("HitDuration is %d", hitDuration);

	char * timeString = pblCgiStrFromTimeAndFormat(time((time_t*)NULL), timeStringFormat);

	char * hitDirectory = pblCgiConfigValue("HitDirectory", "/tmp");
	if (pblCgiStrIsNullOrWhiteSpace(hitDirectory))
	{
		PBL_CGI_TRACE("No value for HitDirectory");
		return 0;
	}
	//PBL_CGI_TRACE("HitDirectory %s", hitDirectory);

	char * hitFileName = pblCgiSprintf("%s_%s.txt", area, timeString);
	char * hitFilePath = pblCgiSprintf("%s/%s", hitDirectory, hitFileName);
	PBL_CGI_TRACE("HitFilePath %s", hitFilePath);

	// produce a hit only if action=refresh
	//
	char * action = pblCgiQueryValue("action");
	if (pblCgiStrEquals("refresh", action))
	{
		FILE * hitFile = pblCgiFopen(hitFilePath, "a+");
		if (hitFile == NULL)
		{
			PBL_CGI_TRACE("Failed to open hitFile %s", hitFilePath);
			return 0;
		}
		fclose(hitFile);
	}

	PBL_FREE(hitFileName);
	PBL_FREE(hitFilePath);
	PBL_FREE(timeString);

	timeString = pblCgiStrFromTimeAndFormat(time((time_t*)NULL) - hitDuration, timeStringFormat);
	hitFileName = pblCgiSprintf("%s_%s.txt", area, timeString);
	hitFilePath = pblCgiSprintf("%s/%s", hitDirectory, hitFileName);

	//PBL_CGI_TRACE("Oldest HitFileName %s", hitFilePath);

	int hitCount = 0;

#ifdef _WIN32

	static char * tag = "getHitCount";

	HANDLE hFind;
	WIN32_FIND_DATA FindData;

	char * pattern = pblCgiSprintf("%s/%s*.*", hitDirectory, area);
	// PBL_CGI_TRACE("FindFirstFile %s", pattern);

	size_t size = strlen(pattern) + 1;
	wchar_t * wFilePattern = pbl_malloc0(tag, sizeof(wchar_t) * size);

	size_t outSize;
	mbstowcs_s(&outSize, wFilePattern, size, pattern, size - 1);

	size = strlen(hitFileName) + 1;
	wchar_t * wHitFileName = pbl_malloc0(tag, sizeof(wchar_t) * size);
	mbstowcs_s(&outSize, wHitFileName, size, hitFileName, size - 1);

	hFind = FindFirstFile(wFilePattern, &FindData);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		PBL_CGI_TRACE("FindFirstFile failed (%d)\n", GetLastError());
		return 0;
	}

	do
	{
		if (wcscmp(wHitFileName, FindData.cFileName) > 0)
		{
			PBL_FREE(hitFilePath);
			char buffer[PBL_CGI_MAX_LINE_LENGTH];
			int size = 0;
			while (FindData.cFileName[size])
			{
				if (size < sizeof(buffer) - 1)
				{
					buffer[size] = (char)FindData.cFileName[size];
					size++;
				}
				else
				{
					break;
				}
			}
			buffer[size] = '\0';
			hitFilePath = pblCgiSprintf("%s/%s", hitDirectory, buffer);
			if (remove(hitFilePath))
			{
				PBL_CGI_TRACE("Error deleting file %s, %d", hitFilePath, errno);
			}
			continue;
		}
		hitCount++;

	} while (FindNextFile(hFind, &FindData));

	FindClose(hFind);

	PBL_FREE(wFilePattern);
	PBL_FREE(wHitFileName);

#else

	int length = strlen(area) + 1;
	struct dirent * entry;
	DIR * directory = opendir(hitDirectory);
	if (!directory)
	{
		PBL_CGI_TRACE("Failed to opendir %s, %d", hitDirectory, errno);
		return 0;
	}

	while ((entry = readdir(directory)) != NULL)
	{
		if (strncmp(hitFileName, entry->d_name, length))
		{
			continue;
		}

		if (strcmp(hitFileName, entry->d_name) > 0)
		{
			PBL_FREE(hitFilePath);
			hitFilePath = pblCgiSprintf("%s/%s", hitDirectory, entry->d_name);
			if (remove(hitFilePath))
			{
				PBL_CGI_TRACE("Error deleting file %s, %d", hitFilePath, errno);
			}
			continue;
		}
		hitCount++;
	}
	closedir(directory);

#endif

	PBL_FREE(hitFileName);
	PBL_FREE(hitFilePath);
	PBL_FREE(timeString);

	return hitCount;
}

static int getDuplicator(char * area, int hitCount)
{
	char * hitCountLevelsString = getAreaConfigValue(area, "HitCountLevels");
	char * hitDuplicatorsString = getAreaConfigValue(area, "HitDuplicators");

	PblList * hitCountLevelsList = pblCgiStrSplitToList(hitCountLevelsString, ",");
	int levelSize = pblListSize(hitCountLevelsList);
	if (levelSize < 1)
	{
		PBL_CGI_TRACE("%s, expecting at least one value for HitCountLevels, value '%s'", area, hitCountLevelsString);

		freeStringList(hitCountLevelsList);
		return 0;
	}

	PblList * hitDuplicatorsList = pblCgiStrSplitToList(hitDuplicatorsString, ",");
	int duplicatorSize = pblListSize(hitDuplicatorsList);
	if (duplicatorSize < 1)
	{
		PBL_CGI_TRACE("%s, expecting at least one value for HitDuplicators, value '%s'", area, hitDuplicatorsString);

		freeStringList(hitCountLevelsList);
		freeStringList(hitDuplicatorsList);
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
			freeStringList(hitCountLevelsList);
			freeStringList(hitDuplicatorsList);
			return rc;
		}
	}

	int rc = atoi(pblListGet(hitDuplicatorsList, duplicatorSize - 1));
	freeStringList(hitCountLevelsList);
	freeStringList(hitDuplicatorsList);
	return rc;
}

static char * changeLat(char * string, int i, int difference)
{
	if (!strstr(string, "\"lat\":"))
	{
		return pblCgiStrDup(string);
	}

	int factor = 1 + (i - 1) / 8;
	int modulo = (i - 1) % 8;

	switch (modulo)
	{
	case 0:
		difference *= factor;
		break;
	case 1:
		difference *= -factor;
		break;
	case 4:
	case 5:
		difference *= factor;
		break;
	case 6:
	case 7:
		difference *= -factor;
		break;
	default:
		return pblCgiStrDup(string);
	}

	char * lat = getNumberString(string, "\"lat\":");
	//PBL_CGI_TRACE("lat=%s", lat);

	char * oldLat = pblCgiSprintf("\"lat\":%s,", lat);
	//PBL_CGI_TRACE("oldLat=%s", oldLat);

	char * newLat = pblCgiSprintf("\"lat\":%d,", atoi(lat) + difference);
	//PBL_CGI_TRACE("newLat=%s", newLat);

	char * replacedLat = pblCgiStrReplace(string, oldLat, newLat);

	PBL_FREE(lat);
	PBL_FREE(oldLat);
	PBL_FREE(newLat);

	return replacedLat;
}

static char * changeLon(char * string, int i, int difference)
{
	if (!strstr(string, "\"lon\":"))
	{
		return pblCgiStrDup(string);
	}

	int factor = 1 + (i - 1) / 8;
	int modulo = (i - 1) % 8;

	switch (modulo)
	{
	case 2:
		difference *= factor;
		break;
	case 3:
		difference *= -factor;
		break;
	case 4:
	case 6:
		difference *= factor;
		break;
	case 5:
	case 7:
		difference *= -factor;
		break;
	default:
		return pblCgiStrDup(string);
	}

	char * lon = getNumberString(string, "\"lon\":");
	//PBL_CGI_TRACE("lon=%s", lon);

	char * oldLon = pblCgiSprintf("\"lon\":%s,", lon);
	//PBL_CGI_TRACE("oldLon=%s", oldLon);

	char * newLon = pblCgiSprintf("\"lon\":%d,", atoi(lon) + difference);
	//PBL_CGI_TRACE("newLon=%s", newLon);

	char * replacedLon = pblCgiStrReplace(string, oldLon, newLon);

	PBL_FREE(lon);
	PBL_FREE(oldLon);
	PBL_FREE(newLon);

	return replacedLon;
}

static PblList * relativeAltList = NULL;

static char * changeRelativeAlt(char * string, int index)
{
	char * tag = "changeRelativeAlt";
	if (!strstr(string, "\"relativeAlt\":"))
	{
		//PBL_CGI_TRACE("No relativeAlt in %s", string);
		return pblCgiStrDup(string);
	}
	if (!relativeAltList)
	{
		char * relativeAltValue = pblCgiConfigValue("RelativeAlt", NULL);
		if (pblCgiStrIsNullOrWhiteSpace(relativeAltValue))
		{
			PBL_CGI_TRACE("No config value for RelativeAlt");

			relativeAltList = pblListNewArrayList();
			if (!relativeAltList)
			{
				pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
			}
			return pblCgiStrDup(string);
		}
		relativeAltList = pblCgiStrSplitToList(relativeAltValue, ",");
		if (pblListIsEmpty(relativeAltList))
		{
			PBL_CGI_TRACE("RelativeAltList is empty");
		}
	}
	if (pblListIsEmpty(relativeAltList))
	{
		return pblCgiStrDup(string);
	}

	char * full = getStringBetween(string, "\"full\":\"", "\"");
	if (pblCgiStrIsNullOrWhiteSpace(full))
	{
		PBL_CGI_TRACE("No value for full in %s", string);
		return pblCgiStrDup(string);
	}

	int listSize = pblListSize(relativeAltList);

	float value = -1000000.0;
	for (int i = 0; i < listSize - 1; i += 2)
	{
		char * l3dName = pblListGet(relativeAltList, i);
		char * valueStr = pblListGet(relativeAltList, i + 1);

		if (pblCgiStrEquals(l3dName, full))
		{
			value = strtof(valueStr, NULL);
			break;
		}
	}
	PBL_FREE(full);

	if (value != -1000000.0)
	{
		double factor = (index + 1) / 2;
		if (!(index % 2))
		{
			factor = -factor;
		}

		char * relativeAltStr = getNumberString(string, "\"relativeAlt\":");
		double relativeAltValue = strtof(relativeAltStr, NULL);

		char * oldRelativeAlt = pblCgiSprintf("\"relativeAlt\":%s,", relativeAltStr);
		//PBL_CGI_TRACE("oldRelativeAlt=%s", oldRelativeAlt);

		char * newRelativeAlt = pblCgiSprintf("\"relativeAlt\":%f,", relativeAltValue + factor * value);
		//PBL_CGI_TRACE("newRelativeAlt=%s", newRelativeAlt);

		char * replacedRelativeAlt = pblCgiStrReplace(string, oldRelativeAlt, newRelativeAlt);

		PBL_FREE(relativeAltStr);
		PBL_FREE(oldRelativeAlt);
		PBL_FREE(newRelativeAlt);

		return replacedRelativeAlt;
	}

	return pblCgiStrDup(string);
}

static void traceDuration()
{
	struct timeval now;
	gettimeofday(&now, NULL);

	unsigned long duration = now.tv_sec * 1000000 + now.tv_usec;
	duration -= pblCgiStartTime.tv_sec * 1000000 + pblCgiStartTime.tv_usec;
	char * string = pblCgiSprintf("%lu", duration);
	PBL_CGI_TRACE("Duration=%s microseconds", string);
}

static int dynamicPois(int argc, char * argv[])
{
	char * tag = "DynamicPois";

	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	pblCgiConfigMap = pblCgiFileToMap(NULL, "../config/poisconfig.txt");

	char * traceFile = pblCgiConfigValue(PBL_CGI_TRACE_FILE, "");
	pblCgiInitTrace(&startTime, traceFile);
	PBL_CGI_TRACE("argc %d argv[0] = %s", argc, argv[0]);

	pblCgiParseQuery(argc, argv);

	char * hostName = pblCgiConfigValue("HostName", "www.mission-base.de");
	if (pblCgiStrIsNullOrWhiteSpace(hostName))
	{
		pblCgiExitOnError("%s: HostName must be given.\n", tag);
	}
	//PBL_CGI_TRACE("HostName=%s", hostName);

	int port = 80;
	char * portString = pblCgiConfigValue("Port", "80");
	if (!pblCgiStrIsNullOrWhiteSpace(portString))
	{
		//PBL_CGI_TRACE("Port=%s", portString);
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
	//PBL_CGI_TRACE("BaseUri=%s", baseUri);

	char * uri = pblCgiSprintf("%s?%s", baseUri, pblCgiQueryString);
	//PBL_CGI_TRACE("Uri=%s", uri);

#ifdef _WIN32

	// Initialize Winsock
	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0)
	{
		pblCgiExitOnError("%s: WSAStartup failed: %d\n", tag, result);
	}
	//PBL_CGI_TRACE("WSAStartup=ok");

#endif

	char * response = getHttpResponse(hostName, port, uri, 16);
	PBL_CGI_TRACE("Response=%s", response);

	char * cookie = getStringBetween(response, "Set-Cookie: ", "\r\n");

	/*
	* check for HTTP error code like HTTP/1.1 500 Server Error
	*/
	char * ptr = strstr(response, "HTTP/");
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
		ptr = strstr(ptr, "\n\n");
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
	response = ptr;

	char * start = "{\"hotspots\":";
	int length = strlen(start);

	if (strncmp(start, response, length))
	{
		fputs("Content-Type: application/json\r\nSet-Cookie: ", stdout);
		fputs(cookie, stdout);
		fputs("\r\n\r\n", stdout);
		fputs(response, stdout);
		PBL_CGI_TRACE("Response does not start with %s, no duplication", start);
		return 0;
	}

	char * latString = pblCgiQueryValue("lat");
	if (pblCgiStrIsNullOrWhiteSpace(latString))
	{
		pblCgiExitOnError("%s: lat needs be given as float in query, got '%s'\n", tag, latString);
	}

	errno = 0;
	float latFloat = strtof(latString, NULL);
	if (latFloat == 0 && errno != 0)
	{
		pblCgiExitOnError("%s: lat needs be given as float in query, got '%s', errno %d\n", tag, latString, errno);
	}
	int latInt = (int)(1000000.0 * latFloat);

	char * lonString = pblCgiQueryValue("lon");
	if (pblCgiStrIsNullOrWhiteSpace(lonString))
	{
		pblCgiExitOnError("%s: lon needs be given as float in query, got '%s'\n", tag, lonString);
	}

	errno = 0;
	float lonFloat = strtof(lonString, NULL);
	if (lonFloat == 0 && errno != 0)
	{
		pblCgiExitOnError("%s: lon needs be given as float in query, got '%s', errno %d\n", tag, lonString, errno);
	}
	int lonInt = (int)(1000000.0 * lonFloat);

	char * area = getArea(latInt, lonInt);
	if (area == NULL)
	{
		fputs("Content-Type: application/json\r\nSet-Cookie: ", stdout);
		fputs(cookie, stdout);
		fputs("\r\n\r\n", stdout);
		fputs(response, stdout);
		PBL_CGI_TRACE("Not in any area, no duplication");
		return 0;
	}

	int numberOfHits = getHitCount(area);
	if (numberOfHits == 0)
	{
		PBL_CGI_TRACE("Hits 0, no duplication");

		fputs("Content-Type: application/json\r\nSet-Cookie: ", stdout);
		fputs(cookie, stdout);
		fputs("\r\n\r\n", stdout);
		fputs(response, stdout);
		return 0;
	}

	int duplicator = getDuplicator(area, numberOfHits);
	if (duplicator <= 1)
	{
		PBL_CGI_TRACE("Hits %d, Duplicator %d, no duplication", numberOfHits, duplicator);

		fputs("Content-Type: application/json\r\nSet-Cookie: ", stdout);
		fputs(cookie, stdout);
		fputs("\r\n\r\n", stdout);
		fputs(response, stdout);
		return 0;
	}
	PBL_CGI_TRACE("Hits %d, Duplicator %d", numberOfHits, duplicator);

	PblStringBuilder * stringBuilder = pblStringBuilderNew();
	if (!stringBuilder)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}

	char * rest = NULL;
	char * hotspotsString = getMatchingString(response + length, '[', ']', &rest);

	//PBL_CGI_TRACE("hotspotsString=%s", hotspotsString);
	//PBL_CGI_TRACE("rest=%s", rest);

	PblList * list = pblListNewArrayList();
	if (!list)
	{
		pblCgiExitOnError("%s: pbl_errno = %d, message='%s'\n", tag, pbl_errno, pbl_errstr);
	}

	ptr = hotspotsString;
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

	fputs("Content-Type: application/json\r\nSet-Cookie: ", stdout);
	fputs(cookie, stdout);
	fputs("\r\n\r\n", stdout);
	putString(start, stringBuilder);
	putString("[", stringBuilder);

	int nPois = pblListSize(list);
	PBL_CGI_TRACE("Number of pois=%d", nPois);

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
				//PBL_CGI_TRACE("hotspot=%s", hotspot);
			}
			else
			{
				char * replacedLat = changeLat(hotspot, i, 100);
				char * replacedLon = changeLon(replacedLat, i, 100);
				char * replacedRelativeAlt = changeRelativeAlt(replacedLon, i);

				char * id = getStringBetween(replacedRelativeAlt, "\"id\":\"", "\"");
				//PBL_CGI_TRACE("id=%s", id);

				char * oldId = pblCgiSprintf("\"id\":\"%s\"", id);
				//PBL_CGI_TRACE("oldId=%s", oldId);

				char * newId = pblCgiSprintf("\"id\":\"%d\"", atoi(id) + idDifference);
				//PBL_CGI_TRACE("newId=%s", newId);

				char * replacedId = pblCgiStrReplace(replacedRelativeAlt, oldId, newId);
				//PBL_CGI_TRACE("replacedId=%s", replacedId);

				putString(replacedId, stringBuilder);

				PBL_FREE(replacedLat);
				PBL_FREE(replacedLon);
				PBL_FREE(replacedRelativeAlt);

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

int main(int argc, char * argv[])
{
	int rc = dynamicPois(argc, argv);
	traceDuration();
	return rc;
}
