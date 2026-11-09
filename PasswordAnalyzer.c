/* =========================================================================
 * Password Security Analyzer (C version)
 * =========================================================================
 *
 * A terminal-based, single-file password auditing tool.
 *
 * Design goals:
 *   - Standard C library only. No OpenSSL, no external crypto/hashing
 *     libraries, no third-party dependencies of any kind, and no
 *     well-known named algorithm (MD5/SHA-*) either. Hashing is done
 *     with a small hand-written mixing function (see Section 1) built
 *     from nothing but XOR, rotate, add and multiply.
 *   - The raw password the user types is NEVER written to disk and is
 *     wiped from memory (memset to zero) as soon as it is no longer
 *     needed. Only its hash digest is ever persisted (in the history
 *     log, for reuse detection), and that digest is one-way in the
 *     sense that it deliberately throws away information (multiple
 *     inputs collapse to the same lane state), even though it offers
 *     none of the formal cryptographic guarantees of SHA-2/SHA-3.
 *
 * Main menu:
 *   1) Check password strength
 *   2) Generate a strong password
 *   3) Exit
 *
 * Hidden/advanced entry points (not shown on the menu, for developers):
 *   ./password_analyzer --selftest   Runs a small internal test suite
 *                                    (fixed regression hash values +
 *                                    a handful of pattern-detection
 *                                    checks) and exits with 0 on success.
 *   ./password_analyzer --help       Prints usage information and exits.
 *
 * Files this program may read/write in its working directory:
 *   common_passwords.txt   A newline-separated wordlist of known weak
 *                           passwords. Auto-created with a small default
 *                           list on first run if it doesn't exist. Feel
 *                           free to replace it with a much larger list.
 *   scoring_config.txt      Point values and length thresholds used by
 *                           the scoring engine. Auto-created with sane
 *                           defaults on first run. Edit it to tune how
 *                           strict the analyzer is.
 *   password_history.log    A log of hash digests (plus timestamps) of
 *                           passwords that have already been checked, so
 *                           the tool can warn you if you re-use an exact
 *                           password you've already tried. No raw
 *                           passwords are ever written here.
 *
 * Compile (Linux/macOS, POSIX):
 *   gcc -O2 -Wall -o password_analyzer password_analyzer.c -lm
 *
 * Run:
 *   ./password_analyzer
 *
 * Note: hidden password input (no terminal echo) uses <termios.h>, which
 * is POSIX (Linux/macOS/WSL). On plain Windows you'd need a different
 * approach (e.g. conio.h's _getch), which is not included here.
 * ========================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <termios.h>
#include <unistd.h>

/* ==========================================================================
 * SECTION 1: Custom Hash Algorithm ("CHA-256", 256-bit / 64 hex chars)
 *
 * This is NOT SHA-256, MD5, or any other published algorithm - it is a
 * small hand-rolled mixing function built only from XOR, bit-rotation,
 * addition and multiplication (all operations any standard C compiler
 * provides natively, so no library of any kind is needed).
 *
 * How it works, at a glance:
 *   1. State is 8 independent 32-bit "lanes" (256 bits total), seeded
 *      with 8 arbitrary distinct constants.
 *   2. Each input byte is folded into one lane at a time using XOR,
 *      addition, a data-dependent rotation, and a multiply by an odd
 *      constant (odd so the multiply never zeroes out entire bit
 *      positions).
 *   3. On finalization, the total input length is mixed into every
 *      lane, then several cross-lane rounds mix each lane together
 *      with two others so a change anywhere in the input has a chance
 *      to ripple through the whole 256-bit state (basic diffusion).
 *   4. Each lane is finally run through its own avalanche step (a
 *      xor-multiply-xor-multiply-xor sequence) so that flipping a
 *      single input bit tends to flip roughly half the output bits.
 *
 * This is built for the purposes of this tool - fingerprinting a
 * password so the raw text never has to be stored, and detecting exact
 * reuse - NOT for cryptographic security. It has not been analyzed for
 * collision resistance and should never be used to protect real
 * secrets in a production system.
 * ========================================================================== */

typedef unsigned char BYTE;
typedef unsigned int  WORD32;

#define CHA_LANES 8

typedef struct {
    WORD32 lane[CHA_LANES];
    unsigned long long total_len;
} CustomHashCtx;

/* Arbitrary distinct 32-bit seed constants - just fixed starting noise,
 * not tied to any published algorithm. */
static const WORD32 CHA_SEED[CHA_LANES] = {
    0x5A17C39Bu, 0x3D9E2F41u, 0x7C4B8A15u, 0x91FE6D22u,
    0x2B7A44C8u, 0x6E1D9F03u, 0x4F82B6E7u, 0x8C35A1D9u
};

/* Odd multiplier constants used during mixing (must be odd so the
 * multiply is a bijection mod 2^32 and never collapses bits to zero). */
#define CHA_MUL_A 0xB55A4F09u
#define CHA_MUL_B 0xD3A2646Du
#define CHA_MUL_C 0x2545F4B1u
#define CHA_MUL_D 0x9E3779B1u

static WORD32 cha_rotl32(WORD32 x, unsigned int r) {
    r &= 31;
    if (r == 0) return x;
    return (x << r) | (x >> (32 - r));
}

static void custom_hash_init(CustomHashCtx *ctx) {
    for (int i = 0; i < CHA_LANES; ++i) ctx->lane[i] = CHA_SEED[i];
    ctx->total_len = 0;
}

/* Folds one byte into the lane state. Called once per input byte. */
static void custom_hash_update_byte(CustomHashCtx *ctx, BYTE b) {
    int idx      = (int)(ctx->total_len % CHA_LANES);
    int neighbor1 = (idx + 1) % CHA_LANES;
    int neighbor2 = (idx + CHA_LANES - 1) % CHA_LANES;

    WORD32 mixed = ctx->lane[idx];
    mixed ^= (WORD32)b + CHA_MUL_D + (ctx->lane[neighbor1] << 5) + (ctx->lane[neighbor2] >> 3);
    mixed  = cha_rotl32(mixed, 1u + (unsigned int)(b % 31));
    mixed *= CHA_MUL_A;
    mixed ^= (mixed >> 11);

    ctx->lane[idx] = mixed;
    ctx->total_len++;
}

static void custom_hash_update(CustomHashCtx *ctx, const BYTE *data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        custom_hash_update_byte(ctx, data[i]);
}

/* Finalizes the hash: mixes in the total length, runs cross-lane
 * diffusion rounds, then avalanches each lane independently. Writes
 * 32 raw output bytes (big-endian per lane) into `out`. */
static void custom_hash_final(CustomHashCtx *ctx, BYTE out[32]) {
    /* Mix total length into every lane, weighted differently per lane
     * so two inputs of the same length don't collide trivially. */
    for (int i = 0; i < CHA_LANES; ++i)
        ctx->lane[i] ^= (WORD32)(ctx->total_len * (WORD32)(i * 2 + 3) + CHA_MUL_C);

    /* Cross-lane diffusion: each lane absorbs two "distant" lanes so a
     * change anywhere in the input can eventually influence every
     * output lane, not just the one it was originally folded into. */
    for (int round = 0; round < 4; ++round) {
        WORD32 next[CHA_LANES];
        for (int i = 0; i < CHA_LANES; ++i) {
            WORD32 a = ctx->lane[i];
            WORD32 b = ctx->lane[(i + 3) % CHA_LANES];
            WORD32 c = ctx->lane[(i + 5) % CHA_LANES];
            a ^= cha_rotl32(b, 7);
            a += cha_rotl32(c, 13);
            a *= CHA_MUL_B;
            a ^= (a >> 15);
            next[i] = a;
        }
        for (int i = 0; i < CHA_LANES; ++i) ctx->lane[i] = next[i];
    }

    /* Per-lane avalanche finishing step. */
    for (int i = 0; i < CHA_LANES; ++i) {
        WORD32 h = ctx->lane[i];
        h ^= (h >> 16);
        h *= CHA_MUL_A;
        h ^= (h >> 13);
        h *= CHA_MUL_C;
        h ^= (h >> 16);
        ctx->lane[i] = h;
    }

    for (int i = 0; i < CHA_LANES; ++i) {
        WORD32 h = ctx->lane[i];
        out[i*4 + 0] = (BYTE)((h >> 24) & 0xff);
        out[i*4 + 1] = (BYTE)((h >> 16) & 0xff);
        out[i*4 + 2] = (BYTE)((h >> 8)  & 0xff);
        out[i*4 + 3] = (BYTE)(h & 0xff);
    }
}

/* Convenience wrapper: hash a null-terminated string -> 64 lowercase hex
 * characters plus a trailing null terminator. `out_hex` must be at least
 * 65 bytes. */
static void custom_hash_hex(const char *str, char out_hex[65]) {
    CustomHashCtx ctx;
    BYTE digest[32];
    custom_hash_init(&ctx);
    custom_hash_update(&ctx, (const BYTE *)str, strlen(str));
    custom_hash_final(&ctx, digest);
    for (int i = 0; i < 32; ++i)
        sprintf(out_hex + i*2, "%02x", digest[i]);
    out_hex[64] = '\0';
}

/* ==========================================================================
 * SECTION 2: Configuration constants and file paths
 * ========================================================================== */

#define COMMON_PW_FILE    "common_passwords.txt"
#define CONFIG_FILE       "scoring_config.txt"
#define HISTORY_FILE      "password_history.log"
#define MAX_LINE          256
#define MAX_TOKENS        48
#define MAX_PASS_LEN      128

static const char *DEFAULT_COMMON_PASSWORDS[] = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "123123", "letmein", "iloveyou", "admin",
    "welcome", "monkey", "dragon", "password1", "qwerty123", "1q2w3e4r",
    "000000", "1234567", "football", "baseball", "trustno1", "sunshine",
    "master", "superman", "batman", "shadow", "michael", "jennifer"
};
#define DEFAULT_COMMON_COUNT (int)(sizeof(DEFAULT_COMMON_PASSWORDS)/sizeof(DEFAULT_COMMON_PASSWORDS[0]))

/* Scoring weights and length thresholds. All of this is loaded from
 * scoring_config.txt at startup (which is auto-created with these exact
 * defaults the first time the program runs), so an operator can retune
 * the analyzer's strictness without touching the source code. */
typedef struct {
    int length_points;
    int upper_points;
    int lower_points;
    int digit_points;
    int special_points;
    int pattern_points;
    int personal_points;
    int common_points;
    int min_length_full;      /* length needed to earn full length_points   */
    int min_length_partial;   /* length needed to earn half length_points   */
} ScoringConfig;

static void set_default_config(ScoringConfig *cfg) {
    cfg->length_points     = 20;
    cfg->upper_points      = 10;
    cfg->lower_points      = 10;
    cfg->digit_points      = 10;
    cfg->special_points    = 10;
    cfg->pattern_points    = 15;
    cfg->personal_points   = 15;
    cfg->common_points     = 10;
    cfg->min_length_full   = 12;
    cfg->min_length_partial = 8;
}

static int config_total_points(const ScoringConfig *cfg) {
    return cfg->length_points + cfg->upper_points + cfg->lower_points +
           cfg->digit_points + cfg->special_points + cfg->pattern_points +
           cfg->personal_points + cfg->common_points;
}

/* ==========================================================================
 * SECTION 3: Small string / IO helpers
 * ========================================================================== */

static void to_lower_str(char *s) {
    for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
}

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

/* Trims leading/trailing whitespace in place. */
static void trim_whitespace(char *s) {
    size_t start = 0;
    size_t len = strlen(s);
    while (start < len && isspace((unsigned char)s[start])) start++;
    size_t end = len;
    while (end > start && isspace((unsigned char)s[end-1])) end--;
    size_t new_len = end - start;
    memmove(s, s + start, new_len);
    s[new_len] = '\0';
}

/* Reverses a null-terminated string into `out` (which must be at least as
 * large as `in`, including the null terminator). */
static void reverse_string(const char *in, char *out, size_t out_size) {
    size_t len = strlen(in);
    if (len >= out_size) len = out_size - 1;
    for (size_t i = 0; i < len; ++i)
        out[i] = in[len - 1 - i];
    out[len] = '\0';
}

/* Reads one line of visible input. Returns 1 on success, 0 on EOF/error
 * (in which case the caller should treat this as "the user is gone" and
 * unwind gracefully rather than looping forever). */
static int read_line(const char *prompt, char *buf, size_t bufsize) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)bufsize, stdin) == NULL) { buf[0] = '\0'; return 0; }
    trim_newline(buf);
    return 1;
}

/* Reads one line of input with terminal echo disabled, for password entry
 * on POSIX terminals. Falls back gracefully (still reads the line, just
 * without hiding it) if stdin isn't a real terminal, e.g. when input is
 * piped in from a script or a test harness. Returns 1 on success, 0 on
 * EOF/error. */
static int read_hidden(const char *prompt, char *buf, size_t bufsize) {
    struct termios oldt, newt;
    int have_tty = (tcgetattr(STDIN_FILENO, &oldt) == 0);
    printf("%s", prompt);
    fflush(stdout);

    if (have_tty) {
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }

    int ok = (fgets(buf, (int)bufsize, stdin) != NULL);
    if (!ok) buf[0] = '\0';
    trim_newline(buf);

    if (have_tty) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    return ok;
}

/* ==========================================================================
 * SECTION 4: Config file load/save
 * ========================================================================== */

static void write_config_file(const ScoringConfig *cfg) {
    FILE *f = fopen(CONFIG_FILE, "w");
    if (!f) return;
    fprintf(f, "# Password Security Analyzer - scoring configuration\n");
    fprintf(f, "# Point values must add up sensibly; the report always\n");
    fprintf(f, "# shows the score out of the live total of these values.\n");
    fprintf(f, "LENGTH_POINTS=%d\n", cfg->length_points);
    fprintf(f, "UPPER_POINTS=%d\n", cfg->upper_points);
    fprintf(f, "LOWER_POINTS=%d\n", cfg->lower_points);
    fprintf(f, "DIGIT_POINTS=%d\n", cfg->digit_points);
    fprintf(f, "SPECIAL_POINTS=%d\n", cfg->special_points);
    fprintf(f, "PATTERN_POINTS=%d\n", cfg->pattern_points);
    fprintf(f, "PERSONAL_POINTS=%d\n", cfg->personal_points);
    fprintf(f, "COMMON_POINTS=%d\n", cfg->common_points);
    fprintf(f, "MIN_LENGTH_FULL=%d\n", cfg->min_length_full);
    fprintf(f, "MIN_LENGTH_PARTIAL=%d\n", cfg->min_length_partial);
    fclose(f);
}

static void ensure_config_file(const ScoringConfig *defaults) {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (f) { fclose(f); return; }
    write_config_file(defaults);
    printf("[info] '%s' not found - created with default scoring weights.\n", CONFIG_FILE);
}

/* Applies KEY=VALUE from one config line to cfg. Unknown keys and blank
 * or comment ('#') lines are silently ignored so the file stays forgiving
 * to hand-edit. */
static void apply_config_line(ScoringConfig *cfg, const char *line) {
    char work[MAX_LINE];
    strncpy(work, line, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';
    trim_whitespace(work);

    if (work[0] == '\0' || work[0] == '#') return;

    char *eq = strchr(work, '=');
    if (!eq) return;
    *eq = '\0';
    char *key = work;
    char *val = eq + 1;
    trim_whitespace(key);
    trim_whitespace(val);
    int n = atoi(val);

    if      (strcmp(key, "LENGTH_POINTS") == 0)      cfg->length_points = n;
    else if (strcmp(key, "UPPER_POINTS") == 0)       cfg->upper_points = n;
    else if (strcmp(key, "LOWER_POINTS") == 0)       cfg->lower_points = n;
    else if (strcmp(key, "DIGIT_POINTS") == 0)       cfg->digit_points = n;
    else if (strcmp(key, "SPECIAL_POINTS") == 0)     cfg->special_points = n;
    else if (strcmp(key, "PATTERN_POINTS") == 0)     cfg->pattern_points = n;
    else if (strcmp(key, "PERSONAL_POINTS") == 0)    cfg->personal_points = n;
    else if (strcmp(key, "COMMON_POINTS") == 0)      cfg->common_points = n;
    else if (strcmp(key, "MIN_LENGTH_FULL") == 0)    cfg->min_length_full = n;
    else if (strcmp(key, "MIN_LENGTH_PARTIAL") == 0) cfg->min_length_partial = n;
    /* unrecognized keys are ignored on purpose */
}

static void load_config(ScoringConfig *cfg) {
    set_default_config(cfg);
    ensure_config_file(cfg);

    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) return;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f))
        apply_config_line(cfg, line);
    fclose(f);
}

/* ==========================================================================
 * SECTION 5: Leetspeak normalization
 *
 * Attackers (and the people trying to defend against them) both know
 * that "p4ssw0rd" is just "password" wearing a costume. We normalize a
 * handful of very common leetspeak substitutions so that both the
 * personal-info check and the common-password check can catch the
 * disguised form too, not just the literal one.
 * ========================================================================== */

static char leet_map(char c) {
    switch (tolower((unsigned char)c)) {
        case '0': return 'o';
        case '1': return 'i';
        case '3': return 'e';
        case '4': return 'a';
        case '5': return 's';
        case '7': return 't';
        case '@': return 'a';
        case '$': return 's';
        case '!': return 'i';
        case '+': return 't';
        default:  return (char)tolower((unsigned char)c);
    }
}

static void normalize_leetspeak(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 1 < out_size; ++i)
        out[j++] = leet_map(in[i]);
    out[j] = '\0';
}

/* ==========================================================================
 * SECTION 6: Common weak password wordlist
 * ========================================================================== */

static void ensure_common_password_file(void) {
    FILE *f = fopen(COMMON_PW_FILE, "r");
    if (f) { fclose(f); return; }

    f = fopen(COMMON_PW_FILE, "w");
    if (!f) {
        printf("[warn] could not create %s (continuing without it)\n", COMMON_PW_FILE);
        return;
    }
    for (int i = 0; i < DEFAULT_COMMON_COUNT; ++i)
        fprintf(f, "%s\n", DEFAULT_COMMON_PASSWORDS[i]);
    fclose(f);
    printf("[info] '%s' not found - created a default list with %d entries.\n",
           COMMON_PW_FILE, DEFAULT_COMMON_COUNT);
}

static int wordlist_contains(const char *needle_lower) {
    FILE *f = fopen(COMMON_PW_FILE, "r");
    if (!f) return 0;

    char line[MAX_LINE];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line);
        to_lower_str(line);
        if (strcmp(line, needle_lower) == 0) { found = 1; break; }
    }
    fclose(f);
    return found;
}

/* Checks the password against the wordlist both as typed and after
 * leetspeak normalization, so "P@ssw0rd" is caught just as "password"
 * would be. */
static int is_common_password(const char *password) {
    ensure_common_password_file();

    char lower[MAX_PASS_LEN];
    strncpy(lower, password, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    to_lower_str(lower);

    if (wordlist_contains(lower)) return 1;

    char normalized[MAX_PASS_LEN];
    normalize_leetspeak(password, normalized, sizeof(normalized));
    if (strcmp(normalized, lower) != 0 && wordlist_contains(normalized)) return 1;

    return 0;
}

/* ==========================================================================
 * SECTION 7: User personal-info tokens
 * ========================================================================== */

typedef struct {
    char username[64];
    char age[16];
    char bdate[32];
    char home[64];
    char tokens[MAX_TOKENS][64];
    int  token_count;
} UserInfo;

static void add_token(UserInfo *ui, const char *tok) {
    if (strlen(tok) < 2) return;               /* skip trivial 1-char tokens */
    if (ui->token_count >= MAX_TOKENS) return;
    char lower[64];
    strncpy(lower, tok, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    to_lower_str(lower);
    for (int i = 0; i < ui->token_count; ++i)   /* avoid duplicates */
        if (strcmp(ui->tokens[i], lower) == 0) return;
    strcpy(ui->tokens[ui->token_count++], lower);
}

/* Adds a field both as a whole token and split into pieces, plus the
 * reversed form of each piece (people sometimes type their name
 * backwards thinking that's clever, e.g. "nhoj" for "john"). */
static void tokenize_field(UserInfo *ui, const char *field) {
    if (field[0] == '\0') return;
    add_token(ui, field);

    char reversed_whole[128];
    reverse_string(field, reversed_whole, sizeof(reversed_whole));
    add_token(ui, reversed_whole);

    char copy[128];
    strncpy(copy, field, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';

    char *tok = strtok(copy, " -/_,.");
    while (tok) {
        add_token(ui, tok);
        char reversed_piece[64];
        reverse_string(tok, reversed_piece, sizeof(reversed_piece));
        add_token(ui, reversed_piece);
        tok = strtok(NULL, " -/_,.");
    }
}

static void collect_user_info(UserInfo *ui) {
    memset(ui, 0, sizeof(*ui));
    printf("\n--- Tell us a bit about yourself ---\n");
    printf("(used only to check if your password is based on personal info; nothing is stored to disk)\n");
    if (!read_line("Username: ", ui->username, sizeof(ui->username))) return;
    if (!read_line("Age: ", ui->age, sizeof(ui->age))) return;
    if (!read_line("Birthdate (e.g. 1998-05-14): ", ui->bdate, sizeof(ui->bdate))) return;
    if (!read_line("Home / city: ", ui->home, sizeof(ui->home))) return;

    tokenize_field(ui, ui->username);
    tokenize_field(ui, ui->age);
    tokenize_field(ui, ui->bdate);
    tokenize_field(ui, ui->home);
}

/* Checks the password (both as typed and leetspeak-normalized) against
 * every collected personal-info token. */
static int contains_personal_info(const char *password, const UserInfo *ui) {
    char pw[MAX_PASS_LEN];
    strncpy(pw, password, sizeof(pw) - 1);
    pw[sizeof(pw) - 1] = '\0';
    to_lower_str(pw);

    char normalized[MAX_PASS_LEN];
    normalize_leetspeak(password, normalized, sizeof(normalized));

    for (int i = 0; i < ui->token_count; ++i) {
        if (strstr(pw, ui->tokens[i]) != NULL) return 1;
        if (strcmp(normalized, pw) != 0 && strstr(normalized, ui->tokens[i]) != NULL) return 1;
    }
    return 0;
}

/* ==========================================================================
 * SECTION 8: Pattern detection (repeats, runs, keyboard walks)
 * ========================================================================== */

/* Common physical keyboard rows (unshifted, QWERTY layout). Any 4+
 * character forward or reverse substring of these counts as a
 * "keyboard walk" - a classic weak-password habit. */
static const char *KEYBOARD_ROWS[] = {
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890"
};
#define KEYBOARD_ROW_COUNT (int)(sizeof(KEYBOARD_ROWS)/sizeof(KEYBOARD_ROWS[0]))

static int contains_keyboard_walk(const char *pw_lower) {
    for (int r = 0; r < KEYBOARD_ROW_COUNT; ++r) {
        const char *row = KEYBOARD_ROWS[r];
        int row_len = (int)strlen(row);

        char reversed_row[16];
        reverse_string(row, reversed_row, sizeof(reversed_row));

        for (int start = 0; start + 4 <= row_len; ++start) {
            char chunk[8];
            strncpy(chunk, row + start, 4);
            chunk[4] = '\0';
            if (strstr(pw_lower, chunk)) return 1;

            char chunk_rev[8];
            strncpy(chunk_rev, reversed_row + start, 4);
            chunk_rev[4] = '\0';
            if (strstr(pw_lower, chunk_rev)) return 1;
        }
    }
    return 0;
}

static int has_repeated_patterns(const char *password) {
    char pw[MAX_PASS_LEN];
    strncpy(pw, password, sizeof(pw) - 1);
    pw[sizeof(pw) - 1] = '\0';
    to_lower_str(pw);
    int len = (int)strlen(pw);

    /* same char 3+ times in a row: "aaa", "111" */
    for (int i = 0; i + 2 < len; ++i)
        if (pw[i] == pw[i+1] && pw[i] == pw[i+2]) return 1;

    /* a 2-4 char chunk repeated back-to-back: "abab", "abcabc" */
    for (int chunk = 2; chunk <= 4; ++chunk)
        for (int i = 0; i + 2*chunk <= len; ++i)
            if (strncmp(pw+i, pw+i+chunk, chunk) == 0) return 1;

    /* sequential ascending/descending run of 4+: "1234", "abcd", "dcba" */
    const char *fwd = "abcdefghijklmnopqrstuvwxyz0123456789";
    char bwd[64];
    int flen = (int)strlen(fwd);
    for (int i = 0; i < flen; ++i) bwd[i] = fwd[flen-1-i];
    bwd[flen] = '\0';

    for (int i = 0; i + 3 < len; ++i) {
        char chunk4[5];
        strncpy(chunk4, pw+i, 4);
        chunk4[4] = '\0';
        if (strstr(fwd, chunk4) || strstr(bwd, chunk4)) return 1;
    }

    /* physical keyboard walks: "qwerty", "asdf", "zxcvb", ... */
    if (contains_keyboard_walk(pw)) return 1;

    return 0;
}

/* ==========================================================================
 * SECTION 9: Entropy estimation (informational only - does not affect score)
 * ========================================================================== */

/* Estimates the size of the character pool the password draws from,
 * based on which classes of characters are present. This is the
 * standard "worst case" estimate used to compute brute-force strength:
 * bits = length * log2(pool_size). */
static int estimate_pool_size(const char *password) {
    int has_lower = 0, has_upper = 0, has_digit = 0, has_special = 0;
    for (const char *p = password; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (islower(c)) has_lower = 1;
        else if (isupper(c)) has_upper = 1;
        else if (isdigit(c)) has_digit = 1;
        else if (isgraph(c)) has_special = 1;
    }
    int pool = 0;
    if (has_lower)   pool += 26;
    if (has_upper)   pool += 26;
    if (has_digit)   pool += 10;
    if (has_special) pool += 32; /* rough count of common printable specials */
    return pool > 0 ? pool : 1;
}

static double estimate_bruteforce_bits(const char *password) {
    int pool = estimate_pool_size(password);
    int len = (int)strlen(password);
    if (len == 0) return 0.0;
    return (double)len * (log((double)pool) / log(2.0));
}

/* Shannon entropy, in bits per character, based on the password's own
 * observed character distribution. This is a different (and usually
 * lower) number than the brute-force pool estimate above - it measures
 * how predictable THIS password's character frequencies are, not how
 * big the theoretical keyspace is. Both are shown for context. */
static double shannon_entropy_per_char(const char *password) {
    int freq[256] = {0};
    int len = (int)strlen(password);
    if (len == 0) return 0.0;

    for (int i = 0; i < len; ++i)
        freq[(unsigned char)password[i]]++;

    double entropy = 0.0;
    for (int c = 0; c < 256; ++c) {
        if (freq[c] == 0) continue;
        double p = (double)freq[c] / (double)len;
        entropy -= p * (log(p) / log(2.0));
    }
    return entropy;
}

/* ==========================================================================
 * SECTION 10: Findings / scoring / report
 * ========================================================================== */

typedef struct {
    char status[8];    /* "OK", "WARN", "FAIL", "INFO" */
    char message[192];
} Finding;

typedef struct {
    Finding items[20];
    int count;
} Findings;

static void add_finding(Findings *f, const char *status, const char *msg) {
    if (f->count >= 20) return;
    strncpy(f->items[f->count].status, status, sizeof(f->items[f->count].status) - 1);
    strncpy(f->items[f->count].message, msg, sizeof(f->items[f->count].message) - 1);
    f->count++;
}

/* Runs every check and returns the score out of config_total_points(cfg).
 * `already_seen` indicates whether this exact password (by hash) has
 * shown up before in the history log; it's reported as an INFO line and
 * does not affect the score. */
static int analyze_password(const char *password, const UserInfo *ui,
                             const ScoringConfig *cfg, int already_seen, Findings *out) {
    int score = 0;
    char msg[192];
    int len = (int)strlen(password);

    /* --- length --- */
    if (len >= cfg->min_length_full) {
        score += cfg->length_points;
        snprintf(msg, sizeof(msg), "Length is %d characters (>=%d).", len, cfg->min_length_full);
        add_finding(out, "OK", msg);
    } else if (len >= cfg->min_length_partial) {
        score += cfg->length_points / 2;
        snprintf(msg, sizeof(msg), "Length is %d characters (%d-%d). %d+ is recommended.",
                 len, cfg->min_length_partial, cfg->min_length_full - 1, cfg->min_length_full);
        add_finding(out, "WARN", msg);
    } else {
        snprintf(msg, sizeof(msg), "Length is only %d characters (<%d).", len, cfg->min_length_partial);
        add_finding(out, "FAIL", msg);
    }

    /* --- character classes --- */
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    for (int i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)password[i];
        if (isupper(c)) has_upper = 1;
        else if (islower(c)) has_lower = 1;
        else if (isdigit(c)) has_digit = 1;
        else if (isgraph(c)) has_special = 1;
    }
    if (has_upper) { score += cfg->upper_points; add_finding(out, "OK", "Contains at least one uppercase letter."); }
    else add_finding(out, "FAIL", "Missing an uppercase letter.");
    if (has_lower) { score += cfg->lower_points; add_finding(out, "OK", "Contains at least one lowercase letter."); }
    else add_finding(out, "FAIL", "Missing a lowercase letter.");
    if (has_digit) { score += cfg->digit_points; add_finding(out, "OK", "Contains at least one digit."); }
    else add_finding(out, "FAIL", "Missing a digit.");
    if (has_special) { score += cfg->special_points; add_finding(out, "OK", "Contains at least one special character."); }
    else add_finding(out, "FAIL", "Missing a special character.");

    /* --- repeated / sequential / keyboard-walk patterns --- */
    if (has_repeated_patterns(password))
        add_finding(out, "FAIL", "Contains repeated, sequential, or keyboard-walk patterns "
                                   "(e.g. 'aaa', '1234', 'abab', 'qwerty').");
    else {
        score += cfg->pattern_points;
        add_finding(out, "OK", "No obvious repeated, sequential, or keyboard-walk patterns detected.");
    }

    /* --- personal info (raw and leetspeak-normalized) --- */
    if (contains_personal_info(password, ui))
        add_finding(out, "FAIL", "Contains part of your personal info (name, age, birthdate, or home) "
                                   "- possibly disguised with leetspeak substitutions.");
    else {
        score += cfg->personal_points;
        add_finding(out, "OK", "Does not contain your personal info, even accounting for leetspeak.");
    }

    /* --- common weak-password list (raw and leetspeak-normalized) --- */
    if (is_common_password(password))
        add_finding(out, "FAIL", "This password (or its de-leetspeaked form) appears in the common weak-password list.");
    else {
        score += cfg->common_points;
        add_finding(out, "OK", "Not found in the common weak-password list.");
    }

    /* --- reuse detection (informational, no score impact) --- */
    if (already_seen)
        add_finding(out, "INFO", "This exact password (matched by hash) has been checked on this system before - consider using a fresh one.");

    /* --- entropy estimates (informational, no score impact) --- */
    double bits = estimate_bruteforce_bits(password);
    double shannon = shannon_entropy_per_char(password);
    snprintf(msg, sizeof(msg),
             "Estimated keyspace strength: ~%.1f bits (pool-based); observed randomness: ~%.2f bits/char (Shannon).",
             bits, shannon);
    add_finding(out, "INFO", msg);

    return score;
}

static const char *rating_label(int score, int max_score) {
    double pct = max_score > 0 ? (100.0 * score / max_score) : 0.0;
    if (pct >= 90) return "VERY STRONG";
    if (pct >= 70) return "STRONG";
    if (pct >= 50) return "MODERATE";
    if (pct >= 30) return "WEAK";
    return "VERY WEAK";
}

static const char *finding_tag(const char *status) {
    if (strcmp(status, "OK") == 0)   return "[OK]  ";
    if (strcmp(status, "WARN") == 0) return "[WARN]";
    if (strcmp(status, "INFO") == 0) return "[INFO]";
    return "[FAIL]";
}

static void print_report(const char *hash_hex, int score, int max_score, const Findings *f) {
    printf("\n================ PASSWORD VALIDATION REPORT ================\n");
    printf("Custom hash digest (password itself is NOT stored): %s\n", hash_hex);
    printf("---------------------------------------------------------------\n");
    for (int i = 0; i < f->count; ++i)
        printf("%s %s\n", finding_tag(f->items[i].status), f->items[i].message);
    printf("---------------------------------------------------------------\n");
    printf("Score: %d / %d\n", score, max_score);
    printf("Rating: %s\n", rating_label(score, max_score));
    printf("===============================================================\n\n");
}

/* ==========================================================================
 * SECTION 11: Password history (hash-only reuse detection)
 * ========================================================================== */

/* Looks for `hash_hex` in the history log and reports whether it was
 * already there, then appends the current attempt (with a timestamp) so
 * future runs can detect this exact password again. Only hashes and
 * timestamps are ever written - never raw passwords. */
static int log_and_check_history(const char *hash_hex) {
    int seen = 0;
    FILE *f = fopen(HISTORY_FILE, "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, hash_hex, 64) == 0) { seen = 1; break; }
        }
        fclose(f);
    }

    FILE *fa = fopen(HISTORY_FILE, "a");
    if (fa) {
        time_t t = time(NULL);
        struct tm *tmv = localtime(&t);
        char ts[32];
        if (tmv) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tmv);
        else strcpy(ts, "unknown-time");
        fprintf(fa, "%s %s\n", hash_hex, ts);
        fclose(fa);
    }
    return seen;
}

/* ==========================================================================
 * SECTION 12: Strong password generator
 * ========================================================================== */

static int random_byte(void) {
    /* Prefer /dev/urandom when available; fall back to rand() otherwise. */
    static FILE *urandom = NULL;
    static int tried = 0;
    if (!tried) { urandom = fopen("/dev/urandom", "rb"); tried = 1; }
    if (urandom) {
        int c = fgetc(urandom);
        if (c != EOF) return c;
    }
    return rand() % 256;
}

static int random_index(int n) {
    if (n <= 0) return 0;
    return random_byte() % n;
}

static void generate_strong_password(char *out, int length) {
    if (length < 8) length = 8;
    if (length > MAX_PASS_LEN - 1) length = MAX_PASS_LEN - 1;

    const char *lower = "abcdefghijklmnopqrstuvwxyz";
    const char *upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *digits = "0123456789";
    const char *special = "!@#$%^&*()-_=+[]{}";
    char all[128];
    snprintf(all, sizeof(all), "%s%s%s%s", lower, upper, digits, special);
    int all_len = (int)strlen(all);

    out[0] = lower[random_index((int)strlen(lower))];
    out[1] = upper[random_index((int)strlen(upper))];
    out[2] = digits[random_index((int)strlen(digits))];
    out[3] = special[random_index((int)strlen(special))];
    for (int i = 4; i < length; ++i)
        out[i] = all[random_index(all_len)];
    out[length] = '\0';

    /* Fisher-Yates shuffle so the guaranteed classes aren't always in the
     * first four positions. */
    for (int i = length - 1; i > 0; --i) {
        int j = random_index(i + 1);
        char tmp = out[i]; out[i] = out[j]; out[j] = tmp;
    }
}

/* ==========================================================================
 * SECTION 13: Session statistics
 * ========================================================================== */

typedef struct {
    int  checks_done;
    int  generated_done;
    long score_sum;
    int  max_score_sum;
    int  highest_pct;
    int  lowest_pct;
} SessionStats;

static void init_stats(SessionStats *s) {
    s->checks_done = 0;
    s->generated_done = 0;
    s->score_sum = 0;
    s->max_score_sum = 0;
    s->highest_pct = -1;
    s->lowest_pct = 101;
}

static void record_check(SessionStats *s, int score, int max_score) {
    s->checks_done++;
    s->score_sum += score;
    s->max_score_sum += max_score;
    int pct = max_score > 0 ? (int)(100.0 * score / max_score) : 0;
    if (pct > s->highest_pct) s->highest_pct = pct;
    if (pct < s->lowest_pct) s->lowest_pct = pct;
}

static void print_session_summary(const SessionStats *s) {
    if (s->checks_done == 0 && s->generated_done == 0) return;
    printf("--------------------- Session summary ------------------------\n");
    if (s->checks_done > 0) {
        double avg_pct = s->max_score_sum > 0 ? (100.0 * s->score_sum / s->max_score_sum) : 0.0;
        printf("Passwords checked: %d\n", s->checks_done);
        printf("Average score: %.1f%%\n", avg_pct);
        printf("Best result: %d%%   Worst result: %d%%\n", s->highest_pct, s->lowest_pct);
    }
    if (s->generated_done > 0)
        printf("Strong passwords generated: %d\n", s->generated_done);
    printf("-----------------------------------------------------------------\n");
}

/* ==========================================================================
 * SECTION 14: Self-test suite (run with --selftest, not part of the menu)
 * ========================================================================== */

/* Regression values captured from this exact custom_hash implementation
 * (see run_self_tests below for how they're used). */
#define CHA_REGRESSION_EMPTY "860b9ebb3d40feeb857aff3336e8e274502fd5406e6f2401dec9ffd11dfb4a45"
#define CHA_REGRESSION_ABC   "f7e73315d38144638ef6bfd36a75631eada76d5276455bab77891540c64b5bc3"

static int run_self_tests(void) {
    int failures = 0;
    char hex[65];

    printf("Running internal self-tests...\n\n");

    /* Fixed regression values for the custom hash function. These were
     * captured from a known-good run of this exact algorithm; since it
     * isn't a published standard, "correct" here means "matches what
     * this code has always produced for this input" - i.e. it catches
     * accidental changes to the mixing logic, not conformance to a spec. */
    custom_hash_hex("", hex);
    if (strcmp(hex, CHA_REGRESSION_EMPTY) == 0)
        printf("[PASS] custom_hash(\"\")\n");
    else { printf("[FAIL] custom_hash(\"\") -> %s\n", hex); failures++; }

    custom_hash_hex("abc", hex);
    if (strcmp(hex, CHA_REGRESSION_ABC) == 0)
        printf("[PASS] custom_hash(\"abc\")\n");
    else { printf("[FAIL] custom_hash(\"abc\") -> %s\n", hex); failures++; }

    /* Basic sanity properties any decent hash should have, checked live
     * rather than against a fixed value: same input -> same output, and
     * different input -> (overwhelmingly likely) different output. */
    char hex_a[65], hex_b[65];
    custom_hash_hex("password123", hex_a);
    custom_hash_hex("password123", hex_b);
    if (strcmp(hex_a, hex_b) == 0)
        printf("[PASS] custom_hash is deterministic (same input -> same digest)\n");
    else { printf("[FAIL] custom_hash gave different digests for the same input\n"); failures++; }

    custom_hash_hex("password124", hex_b);
    if (strcmp(hex_a, hex_b) != 0)
        printf("[PASS] custom_hash output changes when the input changes by one character\n");
    else { printf("[FAIL] custom_hash gave the same digest for two different inputs\n"); failures++; }

    /* Pattern detection: things that SHOULD be flagged */
    const char *weak_examples[] = { "aaaaaaaa", "abcd1234", "qwerty123", "abcabcabc", "9876fedc" };
    for (size_t i = 0; i < sizeof(weak_examples)/sizeof(weak_examples[0]); ++i) {
        if (has_repeated_patterns(weak_examples[i]))
            printf("[PASS] pattern check flags \"%s\"\n", weak_examples[i]);
        else { printf("[FAIL] pattern check missed \"%s\"\n", weak_examples[i]); failures++; }
    }

    /* Pattern detection: a reasonably random string that should NOT be
     * flagged as a repeated/sequential/keyboard-walk pattern. */
    const char *ok_example = "Tr#7hZmQ2Lp";
    if (!has_repeated_patterns(ok_example))
        printf("[PASS] pattern check leaves \"%s\" alone\n", ok_example);
    else { printf("[FAIL] pattern check incorrectly flagged \"%s\"\n", ok_example); failures++; }

    /* Leetspeak normalization sanity check */
    char norm[64];
    normalize_leetspeak("P4ssw0rd!", norm, sizeof(norm));
    if (strcmp(norm, "passwordi") == 0)
        printf("[PASS] leetspeak normalization of \"P4ssw0rd!\" -> \"%s\"\n", norm);
    else { printf("[FAIL] leetspeak normalization gave \"%s\"\n", norm); failures++; }

    printf("\n%d self-test failure(s).\n", failures);
    return failures;
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [--selftest | --help]\n", prog_name);
    printf("  (no arguments)   Run the interactive password analyzer.\n");
    printf("  --selftest       Run the internal test suite and exit.\n");
    printf("  --help           Show this message and exit.\n");
}

static void print_banner(void) {
    printf("+---------------------------------------------------------------+\n");
    printf("|             PASSWORD SECURITY ANALYZER (C, stdlib)            |\n");
    printf("|     passwords are never stored - only a custom hash digest    |\n");
    printf("+---------------------------------------------------------------+\n\n");
}

/* ==========================================================================
 * SECTION 15: Menu flows
 * ========================================================================== */

static void generate_password_flow(const UserInfo *ui_opt, const ScoringConfig *cfg, SessionStats *stats) {
    char len_input[16];
    if (!read_line("Desired length (default 16, min 8): ", len_input, sizeof(len_input))) return;
    int length = 16;
    if (len_input[0] != '\0') {
        int parsed = atoi(len_input);
        if (parsed > 0) length = parsed;
    }

    char new_password[MAX_PASS_LEN];
    generate_strong_password(new_password, length);
    stats->generated_done++;

    printf("\nGenerated password: %s\n", new_password);
    printf("(shown once - copy it now; only its hash can be checked below)\n\n");

    char check_now[8];
    if (read_line("Check the strength of this generated password? (y/n): ", check_now, sizeof(check_now)) &&
        (check_now[0] == 'y' || check_now[0] == 'Y')) {
        UserInfo empty;
        const UserInfo *ui = ui_opt;
        if (!ui) { memset(&empty, 0, sizeof(empty)); ui = &empty; }

        char hash_hex[65];
        custom_hash_hex(new_password, hash_hex);
        int already_seen = log_and_check_history(hash_hex);

        Findings f; f.count = 0;
        int max_score = config_total_points(cfg);
        int score = analyze_password(new_password, ui, cfg, already_seen, &f);
        print_report(hash_hex, score, max_score, &f);
        record_check(stats, score, max_score);
    }

    /* wipe from memory before returning */
    memset(new_password, 0, sizeof(new_password));
}

static void check_password_flow(const ScoringConfig *cfg, SessionStats *stats) {
    UserInfo ui;
    collect_user_info(&ui);

    char pw1[MAX_PASS_LEN], pw2[MAX_PASS_LEN];
    while (1) {
        if (!read_hidden("Enter password: ", pw1, sizeof(pw1))) return;
        if (!read_hidden("Confirm password: ", pw2, sizeof(pw2))) return;
        if (strcmp(pw1, pw2) != 0) {
            printf("Passwords do not match. Try again.\n\n");
            continue;
        }
        if (pw1[0] == '\0') {
            printf("Password cannot be empty.\n\n");
            continue;
        }
        break;
    }

    char hash_hex[65];
    custom_hash_hex(pw1, hash_hex);
    int already_seen = log_and_check_history(hash_hex);

    Findings f; f.count = 0;
    int max_score = config_total_points(cfg);
    int score = analyze_password(pw1, &ui, cfg, already_seen, &f);
    print_report(hash_hex, score, max_score, &f);
    record_check(stats, score, max_score);

    /* wipe raw password from memory now that we're done with it */
    memset(pw1, 0, sizeof(pw1));
    memset(pw2, 0, sizeof(pw2));

    if (max_score > 0 && score < max_score / 2) {
        char choice[8];
        if (read_line("Your password is weak. Generate a strong password now? (y/n): ", choice, sizeof(choice)) &&
            (choice[0] == 'y' || choice[0] == 'Y'))
            generate_password_flow(&ui, cfg, stats);
    }
}

/* ==========================================================================
 * SECTION 16: main
 * ========================================================================== */

int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "--selftest") == 0) {
            int failures = run_self_tests();
            return failures == 0 ? 0 : 1;
        }
        if (strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        printf("Unknown argument: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    srand((unsigned)time(NULL));  /* fallback seed if /dev/urandom is unavailable */

    ScoringConfig cfg;
    load_config(&cfg);

    SessionStats stats;
    init_stats(&stats);

    print_banner();

    while (1) {
        printf("=========== PASSWORD SECURITY ANALYZER ===========\n");
        printf("1. Check password strength\n");
        printf("2. Generate a strong password\n");
        printf("3. Exit\n");

        char choice[8];
        if (!read_line("Select an option (1-3): ", choice, sizeof(choice))) {
            printf("\n");
            break;
        }

        if (strcmp(choice, "1") == 0) {
            check_password_flow(&cfg, &stats);
        } else if (strcmp(choice, "2") == 0) {
            generate_password_flow(NULL, &cfg, &stats);
        } else if (strcmp(choice, "3") == 0) {
            break;
        } else {
            printf("Invalid option. Please choose 1, 2, or 3.\n\n");
        }
    }

    print_session_summary(&stats);
    printf("Goodbye.\n");
    return 0;
}