#include <windows.h>
#include "lwip/sys.h"
#include "lwip/sio.h"

// Required by lwIP for timeouts, even with NO_SYS=1
u32_t sys_now(void) {
    return GetTickCount();
}

// Optional: stub SIO functions to satisfy linker if slipif.c is accidentally included
sio_fd_t sio_open(u8_t devnum) {
    return (sio_fd_t)1; // Stub handle
}

void sio_send(u8_t c, sio_fd_t fd) {
    // No-op
}

u32_t sio_tryread(sio_fd_t fd, u8_t* data, u32_t len) {
    return 0; // No data
}