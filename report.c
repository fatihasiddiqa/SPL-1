#include <stdio.h>

#include "report.h"

void print_report(const AnalysisResult *result)
{
    printf("\n==============================================\n");
    printf("             PASSWORD ANALYSIS REPORT\n");
    printf("==============================================\n");

    printf("Password length          : %d\n", result->length);

    printf("\nCHARACTER COMPOSITION\n");

    printf("Uppercase letters        : %d\n",
           result->uppercase_count);

    printf("Lowercase letters        : %d\n",
           result->lowercase_count);

    printf("Digits                   : %d\n",
           result->digit_count);

    printf("Special characters       : %d\n",
           result->special_count);

    printf("\nPATTERN ANALYSIS\n");

    printf("Repeated characters      : %s\n",
           result->repeated_pattern ? "Detected" : "Not detected");

    printf("Sequential characters    : %s\n",
           result->sequence_pattern ? "Detected" : "Not detected");

    printf("\nPERSONAL INFORMATION CHECK\n");

    printf("Personal information     : %s\n",
           result->personal_match ? "Possible match" : "No match");

    if (result->personal_match)
        printf("Matched information     : %s\n",
               result->matched_personal);

    printf("\nCOMMON PASSWORD CHECK\n");

    printf("Common password similarity: %s\n",
           result->common_match ? "Possible match" : "No match");

    if (result->common_match)
        printf("Similar dictionary entry : %s\n",
               result->matched_common);

    printf("\n==============================================\n");

    printf("SECURITY SCORE: %d / 100\n", result->score);

    printf("SECURITY RATING: %s\n", result->rating);

    printf("==============================================\n");

    printf("\nRECOMMENDATIONS\n");

    if (result->length < 12)
        printf("- Use at least 12 characters.\n");

    if (!result->has_uppercase)
        printf("- Add uppercase letters.\n");

    if (!result->has_lowercase)
        printf("- Add lowercase letters.\n");

    if (!result->has_digit)
        printf("- Add digits.\n");

    if (!result->has_special)
        printf("- Add special characters.\n");

    if (result->repeated_pattern)
        printf("- Avoid three or more repeated characters.\n");

    if (result->sequence_pattern)
        printf("- Avoid simple sequences such as abc or 123.\n");

    if (result->personal_match)
        printf("- Avoid personal information in passwords.\n");

    if (result->common_match)
        printf("- Avoid passwords similar to common passwords.\n");

    if (result->score >= 75)
        printf("- Your password passed the basic checks.\n");

    printf("\nThis is an educational strength estimate.\n");
}
