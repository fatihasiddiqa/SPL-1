#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "input.h"
#include "personal.h"
#include "analyzer.h"
#include "report.h"
#include "generator.h"

#define PASSWORD_SIZE 100
#define COMMON_FILE "common_passwords.txt"

/* Password analysis option */

void password_analysis(void)
{
    PersonalInfo info = {0};

    AnalysisResult result;

    char password[PASSWORD_SIZE] = {0};

    printf("\n====================================\n");
    printf("          PASSWORD ANALYSIS\n");
    printf("====================================\n");

    collect_personal_info(&info);

    if (!read_masked_password(
            "\nEnter password: ",
            password,
            PASSWORD_SIZE))
    {
        printf("\nPassword was empty or could not be read.\n");

        clear_personal_info(&info);

        return;
    }

    result = analyze_password(
        password,
        &info,
        COMMON_FILE
    );

    print_report(&result);

    /* Clear temporary password data. */

    memset(password, 0, sizeof(password));

    clear_personal_info(&info);
}

/* Password generation option */

void password_generation(void)
{
    char password[PASSWORD_SIZE] = {0};

    int length;

    printf("\n====================================\n");
    printf("          PASSWORD GENERATOR\n");
    printf("====================================\n");

    length = read_integer(
        "Enter password length (8-99): ",
        8,
        99
    );

    generate_password(password, length);

    printf("\nGenerated password: %s\n", password);

    printf("\nNote: This generator uses rand().\n");
    printf("It is for educational demonstration only.\n");

    memset(password, 0, sizeof(password));
}

/* Main menu */

int main(void)
{
    int choice;
    srand((unsigned int)time(NULL));

    /* Initialize the random number generator */

    while (1)
    {
        printf("\n====================================\n");
        printf("       PASSWORD SECURITY ANALYZER\n");
        printf("====================================\n");

        printf("1. Analyze Password\n");
        printf("2. Generate Password\n");
        printf("3. Exit\n");

        printf("====================================\n");

        choice = read_integer(
            "Enter your choice: ",
            1,
            3
        );

        switch (choice)
        {
            case 1:
                password_analysis();
                break;

            case 2:
                password_generation();
                break;

            case 3:
                printf("\nThank you for using Password Security Analyzer.\n");
                return 0;
        }
    }

    return 0;
}
