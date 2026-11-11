#include <stdio.h>

#include "input.h"
#include "personal.h"
#include "analyzer.h"
#include "generator.h"

// Password analysis
void password_analysis()
{
    struct PersonalInfo info;

    char password[100];
    

    printf("\n====================================\n");
    printf("          PASSWORD ANALYSIS\n");
    printf("====================================\n");

    collect_personal_info(&info);

    read_line("\nEnter password: ", password, 100);
    read_masked_password("\nEnter password: ", password, 100);

    if (is_empty(password))
    {
        printf("\nPassword cannot be empty.\n");
        clear_personal_info(&info);
        return;
    }

    

    analyze_password(password, &info);

    // Clear temporary sensitive information
    clear_text(password, 100);
    

    clear_personal_info(&info);
}

// Password generation
void password_generation()
{
    char password[100];
    char text[30];

    int length;
    int upper;
    int lower;
    int digits;
    int special;
    int seed;

    printf("\n====================================\n");
    printf("         PASSWORD GENERATOR\n");
    printf("====================================\n");

    read_line("Desired password length (4-64): ",
              text, 30);

    if (!parse_integer(text, &length) ||
        length < 4 || length > 64)
    {
        printf("\nInvalid length.\n");
        return;
    }

    printf("\nChoose character categories.\n");
    printf("Enter 1 for YES and 0 for NO.\n");

    read_line("Include uppercase letters? ", text, 30);

    if (!parse_integer(text, &upper) ||
        (upper != 0 && upper != 1))
    {
        printf("Invalid selection.\n");
        return;
    }

    read_line("Include lowercase letters? ", text, 30);

    if (!parse_integer(text, &lower) ||
        (lower != 0 && lower != 1))
    {
        printf("Invalid selection.\n");
        return;
    }

    read_line("Include digits? ", text, 30);

    if (!parse_integer(text, &digits) ||
        (digits != 0 && digits != 1))
    {
        printf("Invalid selection.\n");
        return;
    }

    read_line("Include special characters? ", text, 30);

    if (!parse_integer(text, &special) ||
        (special != 0 && special != 1))
    {
        printf("Invalid selection.\n");
        return;
    }

    read_line("\nEnter a positive numeric seed: ",
              text, 30);

    if (!parse_integer(text, &seed) || seed <= 0)
    {
        printf("\nInvalid seed.\n");
        return;
    }

    if (generate_password(password,
                          length,
                          upper,
                          lower,
                          digits,
                          special,
                          (unsigned long)seed))
    {
        printf("\n====================================\n");
        printf("       GENERATED PASSWORD\n");
        printf("====================================\n");

        printf("\n%s\n", password);

        printf("\nLength: %d\n", length);

        printf("Uppercase: %s\n", upper ? "Yes" : "No");
        printf("Lowercase: %s\n", lower ? "Yes" : "No");
        printf("Digits: %s\n", digits ? "Yes" : "No");
        printf("Special characters: %s\n",
               special ? "Yes" : "No");

        printf("\nEducational LCG-based generator.\n");
        printf("Not suitable for production security.\n");
    }
    else
    {
        printf("\nPassword generation failed.\n");
    }

    clear_text(password, 100);
}

// Main menu
int main()
{
    char choice[20];

    while (1)
    {
        printf("\n\n");
        printf("========================================\n");
        printf("       PASSWORD SECURITY ANALYZER       \n");
        printf("========================================\n");

        printf("1. Analyze Password\n");
        printf("2. Generate Password\n");
        printf("3. Exit\n");

        printf("========================================\n");

        read_line("Enter your choice: ", choice, 20);

        if (compare_strings(choice, "1"))
        {
            password_analysis();
        }
        else if (compare_strings(choice, "2"))
        {
            password_generation();
        }
        else if (compare_strings(choice, "3"))
        {
            printf("\nThank you for using the program!\n");
            break;
        }
        else
        {
            printf("\nInvalid option. Try again.\n");
        }
    }

    return 0;
}
