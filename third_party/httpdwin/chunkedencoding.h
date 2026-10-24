//Copyright Anoop Kumar Narayanan, 2025

#ifndef CHUNKEDENCODING_H__
#define CHUNKEDENCODING_H__
#include <iostream>
#include <string.h>

#include <httpdlog.h>

class ChunkedEncoding {
public:
	unsigned char data[65536 + 16];
	int  size;
	int  remaining;

	ChunkedEncoding() {
		reset();
	}

	void reset() {
		data[0] = 0;
		size = 0;
		remaining = 0;
	}

	inline void changeToLower(unsigned char* c) {
		if (*c >= 'A' && *c <= 'F')
			*c += 32;
	}

	void setData(char* udata, int len, bool islast = false) {
		if (len < 0) {
			return;
		}

		if (len == 0) {
			if (islast) {
				data[0] = '0';
				data[1] = '\r';
				data[2] = '\n';
				data[3] = '\r';
				data[4] = '\n';
				remaining = 0;
				size = 5;
				return;
			}
			else {
				return;
			}
		}

		size = 0;
		remaining = 0;
		size = len;

		char hexsize[8] = { 0,0,0,0,0,0,0,0 };
		snprintf(hexsize, 5, "%X", size);
		int l = strlen(hexsize);
		//httpdlog("INFO:","hex size = % s, % d  \n", hexsize, l);
		int count = 0;

		if (l == 1) {
			data[0] = hexsize[0];
			changeToLower(&data[0]);
			count++;
		}
		else
			if (l == 2) {
				data[0] = hexsize[0];
				changeToLower(&data[0]);
				data[1] = hexsize[1];
				changeToLower(&data[1]);
				count = 2;
			}
			else
				if (l == 3) {
					data[0] = hexsize[0];
					changeToLower(&data[0]);
					data[1] = hexsize[1];
					changeToLower(&data[1]);
					data[2] = hexsize[2];
					changeToLower(&data[2]);
					count = 3;
				}
				else if (l == 4) {
					data[0] = hexsize[0];
					changeToLower(&data[0]);
					data[1] = hexsize[1];
					changeToLower(&data[1]);
					data[2] = hexsize[2];
					changeToLower(&data[2]);
					data[3] = hexsize[3];
					changeToLower(&data[3]);
					count = 4;
				}

		data[count] = '\r';
		count++;
		data[count] = '\n';
		count++;
		memcpy(&data[count], udata, size);
		data[count + size] = '\r';
		data[count + size + 1] = '\n';
		//httpdlog("INFO:"," Chunk header: %d,%d,%d,%d, %d, %d, - %d \n", data[0], data[1], data[2], data[3], data[4], data[5], count);
		size = count + size + 2;
	}

};


#endif

