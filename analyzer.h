
#ifndef ANALYZER_H
#define ANALYZER_H

#include "personal.h"

typedef struct
{
    int length;

    int uppercase_count;
    int lowercase_count;
    int digit_count;
    int special_count;

    int has_uppercase;
    int has_lowercase;
    int has_digit;
    int has_special;

    int repeated_pattern;
    int sequence_pattern;

    int personal_match;
    int common_match;

    char matched_personal[50];
    char matched_common[60];

    int score;
    char rating[20];

} AnalysisResult;

AnalysisResult analyze_password(
    const char *password,
    const PersonalInfo *info,
    const char *dictionary_file
);

#endif

