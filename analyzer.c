
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "analyzer.h"



static int lcs_length(const char *first, const char *second)
{
    int table[101][101] = {0};
    int i, j;

    int n = strlen(first);
    int m = strlen(second);

    if (n > 100)
        n = 100;

    if (m > 100)
        m = 100;

    for (i = 1; i <= n; i++)
    {
        for (j = 1; j <= m; j++)
        {
            if (tolower((unsigned char)first[i - 1]) ==
                tolower((unsigned char)second[j - 1]))
            {
                table[i][j] = table[i - 1][j - 1] + 1;
            }
            else if (table[i - 1][j] > table[i][j - 1])
            {
                table[i][j] = table[i - 1][j];
            }
            else
            {
                table[i][j] = table[i][j - 1];
            }
        }
    }

    return table[n][m];
}

/* Compare two strings using LCS */

static int similar_enough(
    const char *password,
    const char *candidate,
    int minimum_common
)
{
    int common;

    int shorter_length = strlen(password);
    int candidate_length = strlen(candidate);

    if (candidate_length < shorter_length)
        shorter_length = candidate_length;

    if (shorter_length < minimum_common)
        return 0;

    common = lcs_length(password, candidate);

    return common >= minimum_common &&
           common * 100 >= shorter_length * 60;
}

/* Count character categories */

static void count_characters(
    const char *password,
    AnalysisResult *result
)
{
    int i;
    unsigned char ch;

    for (i = 0; password[i] != '\0'; i++)
    {
        ch = (unsigned char)password[i];

        if (isupper(ch))
            result->uppercase_count++;

        else if (islower(ch))
            result->lowercase_count++;

        else if (isdigit(ch))
            result->digit_count++;

        else
            result->special_count++;
    }

    result->has_uppercase = result->uppercase_count > 0;
    result->has_lowercase = result->lowercase_count > 0;
    result->has_digit = result->digit_count > 0;
    result->has_special = result->special_count > 0;
}



static int detect_repetition(const char *password)
{
    int i;

    for (i = 0; password[i + 2] != '\0'; i++)
    {
        if (password[i] == password[i + 1] &&
            password[i + 1] == password[i + 2])
        {
            return 1;
        }
    }

    return 0;
}



static int detect_sequence(const char *password)
{
    int i;
    int a, b, c;

    for (i = 0; password[i + 2] != '\0'; i++)
    {
        a = (unsigned char)password[i];
        b = (unsigned char)password[i + 1];
        c = (unsigned char)password[i + 2];

        if ((b == a + 1 && c == b + 1) ||
            (b == a - 1 && c == b - 1))
        {
            return 1;
        }
    }

    return 0;
}

/* Check one personal information field */

static int check_personal_field(
    const char *password,
    const char *field,
    char *matched_field,
    int capacity
)
{
    if (field[0] == '\0' || strlen(field) < 4)
        return 0;

    if (similar_enough(password, field, 4))
    {
        snprintf(matched_field, (size_t)capacity, "%s", field);
        return 1;
    }

    return 0;
}

/* Compare password with all personal information */

static int check_personal_information(
    const char *password,
    const PersonalInfo *info,
    char *matched_field,
    int capacity
)
{
    if (check_personal_field(password, info->name,
                             matched_field, capacity))
        return 1;

    if (check_personal_field(password, info->birth_date,
                             matched_field, capacity))
        return 1;

    if (check_personal_field(password, info->city,
                             matched_field, capacity))
        return 1;

    if (check_personal_field(password, info->country,
                             matched_field, capacity))
        return 1;

    if (check_personal_field(password, info->hobby,
                             matched_field, capacity))
        return 1;

    return 0;
}



static int check_common_password_file(
    const char *password,
    const char *filename,
    char *matched_common,
    int capacity
)
{
    FILE *file;
    char word[100];

    file = fopen(filename, "r");

    if (file == NULL)
    {
        printf("\nWarning: Could not open %s.\n", filename);
        return 0;
    }

    while (fgets(word, sizeof(word), file) != NULL)
    {
        word[strcspn(word, "\r\n")] = '\0';

        if (word[0] == '\0')
            continue;

        if (similar_enough(password, word, 5))
        {
            snprintf(matched_common, (size_t)capacity, "%s", word);

            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

static void calculate_score(AnalysisResult *result)
{
    int score = 0;

    if (result->length >= 8)
        score += 20;

    if (result->length >= 12)
        score += 15;

    if (result->length >= 16)
        score += 10;

    if (result->has_uppercase)
        score += 10;

    if (result->has_lowercase)
        score += 10;

    if (result->has_digit)
        score += 10;

    if (result->has_special)
        score += 10;

    if (result->repeated_pattern)
        score -= 10;

    if (result->sequence_pattern)
        score -= 10;

    if (result->personal_match)
        score -= 20;

    if (result->common_match)
        score -= 30;

    if (score < 0)
        score = 0;

    if (score > 100)
        score = 100;

    result->score = score;

    if (score >= 75)
        strcpy(result->rating, "STRONG");

    else if (score >= 50)
        strcpy(result->rating, "MODERATE");

    else
        strcpy(result->rating, "WEAK");
}



AnalysisResult analyze_password(
    const char *password,
    const PersonalInfo *info,
    const char *dictionary_file
)
{
    AnalysisResult result = {0};

    result.length = strlen(password);

    count_characters(password, &result);

    result.repeated_pattern = detect_repetition(password);

    result.sequence_pattern = detect_sequence(password);

    result.personal_match =
        check_personal_information(
            password,
            info,
            result.matched_personal,
            sizeof(result.matched_personal)
        );

    result.common_match =
        check_common_password_file(
            password,
            dictionary_file,
            result.matched_common,
            sizeof(result.matched_common)
        );

    calculate_score(&result);

    return result;
}

