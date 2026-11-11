#ifndef PERSONAL_H
#define PERSONAL_H

typedef struct
{
    char name[50];
    char birth_date[25];
    char city[40];
    char country[40];
    char favorite_fruit[30];
    char favorite_color[30];
    char hobby[30];

} PersonalInfo;

void collect_personal_info(PersonalInfo *info);

void clear_personal_info(PersonalInfo *info);

#endif

