
#include <stdio.h>
#include <conio.h>

#include "input.h"


// Calculate string length
int string_length(char *text)
{
    int i = 0;

    while (text[i] != '\0')
    {
        i++;
    }

    return i;
}


// Convert uppercase character to lowercase
char to_lower(char ch)
{
    if (ch >= 'A' && ch <= 'Z')
    {
        return ch + 32;
    }

    return ch;
}


// Compare two strings
int compare_strings(char *first, char *second)
{
    int i = 0;

    while (first[i] != '\0' && second[i] != '\0')
    {
        if (first[i] != second[i])
        {
            return 0;
        }

        i++;
    }

    return first[i] == '\0' && second[i] == '\0';
}


// Compare strings without considering uppercase/lowercase
int compare_ignore_case(char *first, char *second)
{
    int i = 0;

    while (first[i] != '\0' && second[i] != '\0')
    {
        if (to_lower(first[i]) != to_lower(second[i]))
        {
            return 0;
        }

        i++;
    }

    return first[i] == '\0' && second[i] == '\0';
}


// Check whether one string exists inside another
int contains_text(char *text, char *search)
{
    int i, j;

    int n = string_length(text);
    int m = string_length(search);

    if (m == 0 || m > n)
    {
        return 0;
    }

    for (i = 0; i <= n - m; i++)
    {
        j = 0;

        while (j < m &&
               to_lower(text[i + j]) == to_lower(search[j]))
        {
            j++;
        }

        if (j == m)
        {
            return 1;
        }
    }

    return 0;
}


// Copy one string into another
void copy_text(char *destination, char *source, int size)
{
    int i = 0;

    while (i < size - 1 && source[i] != '\0')
    {
        destination[i] = source[i];
        i++;
    }

    destination[i] = '\0';
}


// Clear a string
void clear_text(char *text, int size)
{
    int i;

    for (i = 0; i < size; i++)
    {
        text[i] = '\0';
    }
}


// Check whether a string is empty
int is_empty(char *text)
{
    return text[0] == '\0';
}


// Read normal visible input
int read_line(char *message, char *text, int size)
{
    int ch;
    int i = 0;

    if (size <= 0)
    {
        return 0;
    }

    printf("%s", message);

    while ((ch = getchar()) != '\n' && ch != EOF)
    {
        if (i < size - 1)
        {
            text[i] = (char)ch;
            i++;
        }
    }

    text[i] = '\0';

    if (ch == EOF && i == 0)
    {
        return 0;
    }

    return 1;
}


// Read a positive integer
int parse_integer(char *text, int *number)
{
    int i = 0;
    int value = 0;

    if (text[0] == '\0')
    {
        return 0;
    }

    while (text[i] != '\0')
    {
        if (text[i] < '0' || text[i] > '9')
        {
            return 0;
        }

        if (value > 214748364 ||
            (value == 214748364 && text[i] > '7'))
        {
            return 0;
        }

        value = value * 10 + text[i] - '0';

        i++;
    }

    *number = value;

    return 1;
}


// Read password with masking
int read_masked_password(char *message, char *password, int size)
{
    int ch;
    int i = 0;

    if (size <= 0)
    {
        return 0;
    }

    printf("%s", message);

    while (1)
    {
        ch = _getch();

        // Enter key
        if (ch == 13)
        {
            break;
        }

        // Backspace key
        else if (ch == 8)
        {
            if (i > 0)
            {
                i--;

                password[i] = '\0';

                printf("\b \b");
            }
        }

        // Ignore special keys
        else if (ch == 0 || ch == 224)
        {
            _getch();
        }

        // Normal printable characters
        else if (ch >= 32 && ch <= 126)
        {
            if (i < size - 1)
            {
                password[i] = (char)ch;

                i++;

                printf("*");
            }
        }
    }

    password[i] = '\0';

    printf("\n");

    return 1;
}
