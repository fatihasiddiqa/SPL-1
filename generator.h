
#ifndef GENERATOR_H
#define GENERATOR_H

int generate_password(
    char password[],
    int length,
    int use_upper,
    int use_lower,
    int use_digits,
    int use_special,
    unsigned long seed
);

#endif
