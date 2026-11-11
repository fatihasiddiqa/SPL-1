
#include <stdio.h>
#include "report.h"

void print_report(struct AnalysisResult result)
{
    printf("\n\n");
    printf("============================================\n");
    printf("          PASSWORD SECURITY REPORT          \n");
    printf("============================================\n");

    printf("\n1. PASSWORD INFORMATION\n");

    printf("Length: %d characters\n", result.length);

    printf("\n2. CHARACTER COMPOSITION\n");

    printf("Uppercase: %d\n", result.uppercase_count);
    printf("Lowercase: %d\n", result.lowercase_count);
    printf("Digits: %d\n", result.digit_count);
    printf("Special characters: %d\n", result.special_count);

    printf("\n3. CHARACTER CATEGORY CHECK\n");

    printf("Uppercase present: %s\n",
           result.uppercase ? "Yes" : "No");

    printf("Lowercase present: %s\n",
           result.lowercase ? "Yes" : "No");

    printf("Digits present: %s\n",
           result.digit ? "Yes" : "No");

    printf("Special characters present: %s\n",
           result.special ? "Yes" : "No");

    printf("\n4. PATTERN DETECTION\n");

    printf("Consecutive repetition: %s\n",
           result.repetition ? "Detected" : "Not detected");

    printf("Repeated pairs: %s\n",
           result.pair_pattern ? "Detected" : "Not detected");

    printf("Alternating pattern: %s\n",
           result.alternating ? "Detected" : "Not detected");

    printf("Sequential pattern: %s\n",
           result.sequence ? "Detected" : "Not detected");

    printf("\n5. PERSONAL INFORMATION CHECK\n");

    if (result.personal_match)
    {
        printf("Personal similarity detected: %s\n",
               result.matched_personal);
    }
    else
    {
        printf("No significant personal similarity detected.\n");
    }

    printf("\n6. DICTIONARY CHECK\n");

    if (result.dictionary_match == 1)
    {
        printf("Dictionary word found: %s\n",
               result.matched_dictionary);
    }
    else if (result.dictionary_match == 2)
    {
        printf("Similar common password found: %s\n",
               result.matched_dictionary);

        printf("Edit distance: %d\n",
               result.dictionary_distance);
    }
    else if (result.dictionary_match == 0)
    {
        printf("No dictionary match detected.\n");
    }
    else
    {
        printf("Dictionary file could not be opened.\n");
    }

    printf("\n7. KEYBOARD PATTERN CHECK\n");

    if (result.keyboard_match == 1)
    {
        printf("Keyboard pattern detected: %s\n",
               result.matched_keyboard);
    }
    else if (result.keyboard_match == 0)
    {
        printf("No keyboard pattern detected.\n");
    }
    else
    {
        printf("Keyboard database unavailable.\n");
    }

    printf("\n8. ENTROPY ESTIMATION\n");

    printf("Character pool size: %d\n", result.entropy_pool);

    printf("Estimated entropy: %.2f bits\n",
           result.entropy);

    printf("\n9. FINAL SECURITY RESULT\n");

    printf("Security score: %d / 100\n",
           result.score);

    printf("Rating: %s\n", result.rating);

    printf("\n10. RECOMMENDATIONS\n");

    if (result.length < 12)
        printf("- Increase password length to at least 12 characters.\n");

    if (!result.uppercase)
        printf("- Add uppercase letters.\n");

    if (!result.lowercase)
        printf("- Add lowercase letters.\n");

    if (!result.digit)
        printf("- Include digits.\n");

    if (!result.special)
        printf("- Include special characters.\n");

    if (result.repetition)
        printf("- Avoid repeating the same character several times.\n");

    if (result.pair_pattern)
        printf("- Avoid repeated pairs such as aabb.\n");

    if (result.alternating)
        printf("- Avoid alternating patterns such as abab.\n");

    if (result.sequence)
        printf("- Avoid sequential characters such as 123 or abc.\n");

    if (result.personal_match)
        printf("- Remove personal information from your password.\n");

    if (result.dictionary_match == 1 ||
        result.dictionary_match == 2)
    {
        printf("- Avoid common words and simple variations of them.\n");
    }

    if (result.keyboard_match == 1)
        printf("- Avoid predictable keyboard sequences.\n");

    if (result.length >= 12 &&
        !result.repetition &&
        !result.sequence &&
        !result.personal_match &&
        result.dictionary_match == 0 &&
        result.keyboard_match == 0)
    {
        printf("- No major weakness was found by the implemented checks.\n");
    }

    printf("\n============================================\n");
}
