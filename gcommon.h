#pragma once

#include <cassert>
#include <cstdint>
#include <chrono>
#include "gmac.h"
#include "gtrace.h"

typedef uint8_t le8_t;
typedef uint16_t le16_t;
typedef uint32_t le32_t;
typedef uint64_t le64_t;

typedef void *pvoid;
typedef char *pchar;
typedef unsigned char *puchar;

typedef std::chrono::high_resolution_clock::time_point Clock;
typedef std::chrono::high_resolution_clock::duration Diff;
typedef std::chrono::high_resolution_clock Timer;

void dump(unsigned char* buf, int size);
