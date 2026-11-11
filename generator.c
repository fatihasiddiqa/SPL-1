
#include "generator.h"
#include "pattern.h"

unsigned long custom_random(unsigned long *seed)
{
    *seed = (*seed * 1103515245UL + 12345UL);

    return (*seed / 65536UL) % 32768UL;
}

char random_character(char characters[],
                      unsigned long *seed)
{
    int i = 0;

    while (characters[i] != '\0')
    {
        i++;
    }

    return characters[custom_random(seed) % i];
}

int generate_password(char password[],
                      int length,
                      int use_upper,
                      int use_lower,
                      int use_digits,
                      int use_special,
                      unsigned long seed)
{
    char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char lower[] = "abcdefghijklmnopqrstuvwxyz";
    char digits[] = "0123456789";
    char special[] = "!@#$%&*?";

    char all[100];

    int categories = 0;
    int i = 0;
    int j = 0;
    int position;
    int attempt;

    char temp;

    if (length < 4 || length > 64)
    {
        return 0;
    }

    if (!use_upper && !use_lower &&
        !use_digits && !use_special)
    {
        return 0;
    }

    if (use_upper) categories++;
    if (use_lower) categories++;
    if (use_digits) categories++;
    if (use_special) categories++;

    if (length < categories)
    {
        return 0;
    }

    if (seed == 0)
    {
        return 0;
    }

    // Build the allowed character pool
    if (use_upper)
    {
        while (upper[i] != '\0')
            all[j++] = upper[i++];

        i = 0;
    }

    if (use_lower)
    {
        while (lower[i] != '\0')
            all[j++] = lower[i++];

        i = 0;
    }

    if (use_digits)
    {
        while (digits[i] != '\0')
            all[j++] = digits[i++];

        i = 0;
    }

    if (use_special)
    {
        while (special[i] != '\0')
            all[j++] = special[i++];

        i = 0;
    }

    all[j] = '\0';

    // Try several candidates
    for (attempt = 0; attempt < 30; attempt++)
    {
        i = 0;

        // Guarantee one character per selected category
        if (use_upper)
            password[i++] = random_character(upper, &seed);

        if (use_lower)
            password[i++] = random_character(lower, &seed);

        if (use_digits)
            password[i++] = random_character(digits, &seed);

        if (use_special)
            password[i++] = random_character(special, &seed);

        // Fill remaining positions
        while (i < length)
        {
            password[i] = random_character(all, &seed);
            i++;
        }

        password[length] = '\0';

        // Shuffle
        for (i = length - 1; i > 0; i--)
        {
            position = custom_random(&seed) % (i + 1);

            temp = password[i];
            password[i] = password[position];
            password[position] = temp;
        }

        // Reject obvious patterns
        if (!detect_repetition(password) &&
            !detect_sequence(password) &&
            !detect_alternating(password))
        {
            return 1;
        }
    }

    // Return the final candidate if all attempts
    // happened to contain a detected pattern.
    return 1;
}
