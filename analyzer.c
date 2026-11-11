
#include <stdio.h>
#include <math.h>

#include "analyzer.h"
#include "input.h"
#include "pattern.h"
#include "dictionary.h"
#include "report.h"
#include "personal.h"


void count_characters(char *password,
                      struct AnalysisResult *result)
{
    int i = 0;
    char ch;

    result->uppercase_count = 0;
    result->lowercase_count = 0;
    result->digit_count = 0;
    result->special_count = 0;

    while (password[i] != '\0')
    {
        ch = password[i];

        if (ch >= 'A' && ch <= 'Z')
        {
            result->uppercase_count++;
        }
        else if (ch >= 'a' && ch <= 'z')
        {
            result->lowercase_count++;
        }
        else if (ch >= '0' && ch <= '9')
        {
            result->digit_count++;
        }
        else
        {
            result->special_count++;
        }

        i++;
    }

    result->uppercase = result->uppercase_count > 0;
    result->lowercase = result->lowercase_count > 0;
    result->digit = result->digit_count > 0;
    result->special = result->special_count > 0;
}


void calculate_entropy(struct AnalysisResult *result)
{
    int pool = 0;

    if (result->uppercase)
        pool += 26;

    if (result->lowercase)
        pool += 26;

    if (result->digit)
        pool += 10;

    if (result->special)
    pool += 8;

    result->entropy_pool = pool;

    if (pool > 1)
    {
        result->entropy =
            result->length * (log((double)pool) / log(2.0));
    }
    else
    {
        result->entropy = 0.0;
    }
}


void calculate_score(struct AnalysisResult *result)
{
    int score = 0;

    // Length points
    if (result->length >= 8)
        score += 20;

    if (result->length >= 12)
        score += 15;

    if (result->length >= 16)
        score += 10;


    // Character diversity
    if (result->uppercase)
        score += 10;

    if (result->lowercase)
        score += 10;

    if (result->digit)
        score += 10;

    if (result->special)
        score += 10;


    // Entropy contribution
    if (result->entropy >= 50)
        score += 10;


    // Weakness penalties
    if (result->repetition)
        score -= 10;

    if (result->pair_pattern)
        score -= 10;

    if (result->alternating)
        score -= 10;

    if (result->sequence)
        score -= 15;

    if (result->personal_match)
        score -= 20;

    if (result->dictionary_match == 1)
        score -= 30;

    if (result->dictionary_match == 2)
        score -= 20;

    if (result->keyboard_match == 1)
        score -= 15;


    // Limit score
    if (score < 0)
        score = 0;

    if (score > 100)
        score = 100;

    result->score = score;


    // Assign rating
    if (result->dictionary_match == 1)
    {
        copy_text(result->rating, "VERY WEAK", 30);
    }
    else if (score >= 75)
    {
        copy_text(result->rating, "STRONG", 30);
    }
    else if (score >= 50)
    {
        copy_text(result->rating, "MODERATE", 30);
    }
    else
    {
        copy_text(result->rating, "WEAK", 30);
    }
}


void analyze_password(char *password,
                      struct PersonalInfo *info)
{
    struct AnalysisResult result;

    int distance = -1;

    result.length = string_length(password);

    clear_text(result.matched_personal, 50);
    clear_text(result.matched_dictionary, 100);
    clear_text(result.matched_keyboard, 80);
    clear_text(result.rating, 30);


    // Character composition
    count_characters(password, &result);


    // Pattern detection
    result.repetition = detect_repetition(password);

    result.pair_pattern = detect_pair_pattern(password);

    result.alternating = detect_alternating(password);

    result.sequence = detect_sequence(password);


    // Personal information similarity
    result.personal_match =
        check_personal_similarity(
            password,
            info,
            result.matched_personal,
            50
        );


    // Dictionary search and edit distance
    result.dictionary_match =
        check_dictionary(
            password,
            "common.txt",
            result.matched_dictionary,
            100,
            &distance
        );

    result.dictionary_distance = distance;


    // Keyboard pattern detection
    result.keyboard_match =
        detect_keyboard_pattern(
            password,
            result.matched_keyboard,
            80
        );


    // Entropy estimation
    calculate_entropy(&result);


    // Final scoring
    calculate_score(&result);


    // Display report
    print_report(result);
}

