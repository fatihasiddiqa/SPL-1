#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "input.h"

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void read_line(const char *message, char *buffer, size_t size)
{
    size_t length;
    int ch;

    if (size == 0)
        return;

    printf("%s", message);

    if (fgets(buffer, (int)size, stdin) == NULL)
    {
        buffer[0] = '\0';
        return;
    }

    length = strlen(buffer);

    if (length > 0 && buffer[length - 1] == '\n')
    {
        buffer[length - 1] = '\0';
    }
    else
    {
        while ((ch = getchar()) != '\n' && ch != EOF)
        {
        }
    }
}

int read_integer(const char *message, int minimum, int maximum)
{
    char buffer[100];
    char *end;
    long value;

    while (1)
    {
        read_line(message, buffer, sizeof(buffer));

        value = strtol(buffer, &end, 10);

        while (isspace((unsigned char)*end))
            end++;

        if (buffer[0] != '\0' && *end == '\0' &&
            value >= minimum && value <= maximum)
        {
            return (int)value;
        }

        printf("Invalid input. Enter a number from %d to %d.\n",
               minimum, maximum);
    }
}

int read_masked_password(const char *message, char *password, int size)
{
    int index = 0;
    int ch;

    if (size <= 1)
        return 0;

    printf("%s", message);
    fflush(stdout);

#ifdef _WIN32

    while ((ch = _getch()) != '\r')
    {
        if (ch == 3)
            return 0;

        if (ch == '\b')
        {
            if (index > 0)
            {
                index--;
                printf("\b \b");
                fflush(stdout);
            }
        }
        else if (ch >= 32 && ch <= 126 && index < size - 1)
        {
            password[index++] = (char)ch;
            putchar('*');
            fflush(stdout);
        }
    }

#else

    {
        struct termios old_settings;
        struct termios new_settings;

        if (tcgetattr(STDIN_FILENO, &old_settings) != 0)
        {
            printf("\nPassword input could not be masked on this terminal.\n");
            return 0;
        }

        new_settings = old_settings;
        new_settings.c_lflag &= (tcflag_t)~ECHO;
        new_settings.c_lflag |= (tcflag_t)ICANON;

        tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);

        while ((ch = getchar()) != '\n' && ch != EOF)
        {
            if (ch == 127 || ch == 8)
            {
                if (index > 0)
                {
                    index--;
                    printf("\b \b");
                    fflush(stdout);
                }
            }
            else if (ch >= 32 && ch <= 126 && index < size - 1)
            {
                password[index++] = (char)ch;
                putchar('*');
                fflush(stdout);
            }
        }

        tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    }

#endif

    password[index] = '\0';

    printf("\n");

    return index;
}
