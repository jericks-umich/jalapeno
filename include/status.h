#ifndef STATUS_H
#define STATUS_H

#define J_MK_ERROR(x)       (0x00000000|(x))

typedef enum {
  J_OK 				= J_MK_ERROR(0x8000),
  J_CANT_OPEN_FILE 	= J_MK_ERROR(0x8001),
} jalapeno_status_t;

#endif // STATUS_H
