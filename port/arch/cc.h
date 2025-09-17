#pragma once

#include <stdint.h>
#include <stdio.h>
#include <errno.h>

// Integer types
typedef uint8_t   u8_t;
typedef int8_t    s8_t;
typedef uint16_t  u16_t;
typedef int16_t   s16_t;
typedef uint32_t  u32_t;
typedef int32_t   s32_t;
typedef uintptr_t mem_ptr_t;

// Format macros for debug printing
#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"

// Diagnostic output
#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { printf("Assert failed: %s\n", x); } while (0)

#ifdef _MSC_VER
  #define PACK_STRUCT_BEGIN __pragma(pack(push, 1))
  #define PACK_STRUCT_STRUCT
  #define PACK_STRUCT_END   __pragma(pack(pop))
  #define PACK_STRUCT_FIELD(x) x
#else
  // For GCC/Clang or MinGW (if needed)
  #define PACK_STRUCT_BEGIN
  #define PACK_STRUCT_STRUCT __attribute__((__packed__))
  #define PACK_STRUCT_END
  #define PACK_STRUCT_FIELD(x) x
#endif

// Protect macros (no RTOS / NO_SYS = 1)
#define SYS_ARCH_DECL_PROTECT(x)
#define SYS_ARCH_PROTECT(x)
#define SYS_ARCH_UNPROTECT(x)

// Fallback errno values
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef ENOSYS
#define ENOSYS 38
#endif