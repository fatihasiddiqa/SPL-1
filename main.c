#include <stdio.h>
#include <string.h>
#include "password_input.h"
#include "analyzer.h"
#include "file_handler.h"

#define MAX_USERNAME 50
#define MAX_PASSWORD 256

static void clear_input_buffer(void) {
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        /* discard remaining input */
    }
}

int main(void) {
    int choice = 0;
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char confirmation[MAX_PASSWORD];

    do {
        printf("\n====================================\n");
        printf("       PASSWORD SECURITY ANALYZER\n");
        printf("====================================\n");
        printf("1. Check Password\n");
        printf("2. Exit\n");
        printf("------------------------------------\n");
        printf("Enter choice: ");

        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter 1 or 2.\n");
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        if (choice == 1) {
            printf("\nEnter username: ");
            if (fgets(username, sizeof(username), stdin) == NULL) {
                printf("Could not read username.\n");
                continue;
            }
            username[strcspn(username, "\n")] = '\0';

            if (username[0] == '\0') {
                strcpy(username, "Anonymous");
            }

            printf("Enter password: ");
            if (!read_masked_password(password, sizeof(password))) {
                printf("\nCould not read password.\n");
                continue;
            }

            printf("Confirm password: ");
            if (!read_masked_password(confirmation, sizeof(confirmation))) {
                printf("\nCould not read confirmation.\n");
                secure_clear(password, sizeof(password));
                continue;
            }

            if (strcmp(password, confirmation) != 0) {
                printf("\nPasswords do not match. Please try again.\n");
                secure_clear(password, sizeof(password));
                secure_clear(confirmation, sizeof(confirmation));
                continue;
            }

            printf("\n\nAnalyzing password...\n");
            analyze_password(password, username);

            /* Passwords are never written to disk. */
            secure_clear(password, sizeof(password));
            secure_clear(confirmation, sizeof(confirmation));
            printf("\nYour password has not been saved.\n");

        } else if (choice == 2) {
            printf("\nThank you for using Password Security Analyzer.\n");
        } else {
            printf("\nInvalid choice. Please select 1 or 2.\n");
        }

    } while (choice != 2);

    return 0;
}