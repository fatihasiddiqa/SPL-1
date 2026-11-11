#ifndef INPUT_H
#define INPUT_H

#include <stddef.h>

void read_line(const char *message, char *buffer, size_t size);

int read_integer(const char *message, int minimum, int maximum);

int read_masked_password(const char *message, char *password, int size);

#endif

