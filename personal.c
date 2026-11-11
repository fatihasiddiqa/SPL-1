
#include <stdio.h>
#include <stddef.h>

#include "personal.h"
#include "input.h"
#include "dp.h"


// Collect personal information
void collect_personal_info(struct PersonalInfo *info)
{
    printf("\n========== PERSONAL INFORMATION ==========\n");

    read_line("Enter your name: ", info->name, 50);

    read_line("Enter birth date (DDMMYYYY): ",
              info->birth_date, 30);

    read_line("Enter country: ",
              info->country, 40);

    read_line("Enter city: ",
              info->city, 40);

    read_line("Favourite fruit: ",
              info->favorite_fruit, 30);

    read_line("Favourite colour: ",
              info->favorite_color, 30);

    read_line("Hobby: ",
              info->hobby, 30);
}


// Check password against one personal information field
int check_field(
    const char *password,
    const char *field,
    char *matched,
    size_t size
)
{
    int length;
    int common;
    int substring;

    length = string_length((char *)field);

    if (length < 4)
    {
        return 0;
    }

    // Direct substring matching
    if (contains_text((char *)password, (char *)field))
    {
        copy_text(matched, (char *)field, (int)size);
        return 1;
    }

    // Longest common substring
    substring = longest_common_substring(
        (char *)password,
        (char *)field
    );

    if (substring >= 4)
    {
        copy_text(matched, (char *)field, (int)size);
        return 1;
    }

    // Longest common subsequence
    common = lcs_length(
        (char *)password,
        (char *)field
    );

    if (common >= 4 &&
        common * 100 >= length * 60)
    {
        copy_text(matched, (char *)field, (int)size);
        return 1;
    }

    return 0;
}


// Check all personal information fields
int check_personal_similarity(
    const char *password,
    const struct PersonalInfo *info,
    char *matched_field,
    size_t matched_size
)
{
    clear_text(matched_field, (int)matched_size);

    if (check_field(password, info->name,
                    matched_field, matched_size))
        return 1;

    if (check_field(password, info->birth_date,
                    matched_field, matched_size))
        return 1;

    if (check_field(password, info->country,
                    matched_field, matched_size))
        return 1;

    if (check_field(password, info->city,
                    matched_field, matched_size))
        return 1;

    if (check_field(password, info->favorite_fruit,
                    matched_field, matched_size))
        return 1;

    if (check_field(password, info->favorite_color,
                    matched_field, matched_size))
        return 1;

    if (check_field(password, info->hobby,
                    matched_field, matched_size))
        return 1;

    return 0;
}


// Clear personal information from temporary memory
void clear_personal_info(struct PersonalInfo *info)
{
    clear_text(info->name, 50);
    clear_text(info->birth_date, 30);
    clear_text(info->country, 40);
    clear_text(info->city, 40);
    clear_text(info->favorite_fruit, 30);
    clear_text(info->favorite_color, 30);
    clear_text(info->hobby, 30);
}


