#include <stdlib.h>

#include "generator.h"

void generate_password(char *password, int length)
{
    const char uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char lowercase[] = "abcdefghijklmnopqrstuvwxyz";
    const char digits[] = "0123456789";
    const char special[] = "!@#$%&*?";
    const char all[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789!@#$%&*?";

    int i;
    int position;
    char temporary;

    if (length < 8)
        length = 8;

    /* Guarantee at least one character from every category. */
    password[0] = uppercase[rand() % 26];
    password[1] = lowercase[rand() % 26];
    password[2] = digits[rand() % 10];
    password[3] = special[rand() % 8];

    for (i = 4; i < length; i++)
        password[i] = all[rand() % (int)(sizeof(all) - 1)];

    password[length] = '\0';

    /* Fisher-Yates shuffle so the first four positions are not predictable. */
    for (i = length - 1; i > 0; i--)
    {
        position = rand() % (i + 1);
        temporary = password[i];
        password[i] = password[position];
        password[position] = temporary;
    }
}
