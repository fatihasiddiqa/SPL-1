#include <stdio.h>
#include <string.h>

#include "personal.h"
#include "input.h"

void collect_personal_info(PersonalInfo *info)
{
    printf("\n========== PERSONAL INFORMATION ==========\n");

    read_line("Enter your name: ",
              info->name,
              sizeof(info->name));

    read_line("Enter your birth date (DD-MM-YYYY): ",
              info->birth_date,
              sizeof(info->birth_date));

    read_line("Enter your city: ",
              info->city,
              sizeof(info->city));

    read_line("Enter your country: ",
              info->country,
              sizeof(info->country));

    read_line("Enter your hobby: ",
              info->hobby,
              sizeof(info->hobby));
}

void clear_personal_info(PersonalInfo *info)
{
    memset(info, 0, sizeof(*info));
}


