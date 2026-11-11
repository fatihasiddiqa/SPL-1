
#ifndef REPORT_H
#define REPORT_H

struct AnalysisResult
{
    int length;

    int uppercase_count;
    int lowercase_count;
    int digit_count;
    int special_count;

    int uppercase;
    int lowercase;
    int digit;
    int special;

    int repetition;
    int pair_pattern;
    int alternating;
    int sequence;

    int personal_match;
    int dictionary_match;
    int keyboard_match;

    int dictionary_distance;

    int entropy_pool;
    int score;

    double entropy;

    char matched_personal[50];
    char matched_dictionary[100];
    char matched_keyboard[80];

    char rating[30];
};

void print_report(struct AnalysisResult result);

#endif
