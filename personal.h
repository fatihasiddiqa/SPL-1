
#ifndef PERSONAL_H
#define PERSONAL_H

#include <stddef.h>

struct PersonalInfo
{
    char name[50];
    char birth_date[30];
    char country[40];
    char city[40];
    char favorite_fruit[30];
    char favorite_color[30];
    char hobby[30];
};

void collect_personal_info(struct PersonalInfo *info);

int check_personal_similarity(
    const char *password,
    const struct PersonalInfo *info,
    char *matched_field,
    size_t matched_size
);

void clear_personal_info(struct PersonalInfo *info);

#endif

