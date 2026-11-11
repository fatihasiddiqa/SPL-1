
#ifndef INPUT_H
#define INPUT_H

int string_length(char *text);

char to_lower(char ch);

int compare_strings(char *first, char *second);

int compare_ignore_case(char *first, char *second);

int contains_text(char *text, char *search);

void copy_text(char *destination, char *source, int size);

void clear_text(char *text, int size);

int is_empty(char *text);

int read_line(char *message, char *text, int size);

int parse_integer(char *text, int *number);

// Read password without displaying actual characters
int read_masked_password(char *message, char *password, int size);

#endif

