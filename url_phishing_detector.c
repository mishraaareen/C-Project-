#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#define MAX_URL_LEN 2048

void newline_trim(char *);
char *get_domain_pointer(char *);
int check_ip_address(char *);
int check_len(const char *);
int check_dot_hostname(char *);
int dotScore( char *);
int check_symbol(const char *);
void to_lower(const char *, char *, int);
int check_suspicious_word(const char *);
int check_hyphen(char *);
int check_http(const char *);
int phishing_score(char *);

// to trim newline from string
void newline_trim(char *s)
{
    int len = strlen(s);

    if (len > 0 && s[len - 1] == '\n')
        s[len - 1] = '\0';
}

// to get domain starting pointer
char *get_domain_pointer(char *url)
{
    if (strncmp(url, "http://", 7) == 0)
        return url + 7;

    else if (strncmp(url, "https://", 8) == 0)
        return url + 8;

    else
        return url;
}

// To check if domain is an ip address
int check_ip_address(char *url)
{
    char *pt = get_domain_pointer(url);

    char add[250];
    int i = 0;
    while (*pt != '\0' && *pt != '/' && i < 250)
    {
        add[i++] = *pt++;
    }
    add[i] = '\0';
    // to check no of dots
    int dot_count = 0;
    for (int i = 0; add[i] != '\0'; i++)
    {

        if (add[i] == '.')
            dot_count++;
        else if (!isdigit((unsigned char)add[i]))
            return 0;
    }

    if (dot_count >= 3)
        return 3; // higher count = more suspicious

    return 0;
}

// to check length of an url
int check_len(const char *url)
{
    int len = strlen(url);

    if (len > 150)
        return 3;
    else if (len > 100)
        return 2;
    else if (len > 75)
        return 1 ;
    else return 0;
}

// to count number of dots in hostname before first occurence
int check_dot_hostname(char *url)
{
    const char *pt = get_domain_pointer(url);

    int c_dot = 0;
    while (*pt != '\0' && *pt != '/')
    {
        if (*pt == '.')
            c_dot++;
        pt++;
    }
    return c_dot;
}

// To count dot score
int dotScore(char *url)
{
    int dots = check_dot_hostname(url);

    if (dots >= 4)
        return 3;
    else if (dots == 3)
        return 2 ;
    else if (dots == 2)
        return 1 ;
    return 0;
}

// To check @ symbol
int check_symbol(const char *url)
{

    if (strchr(url, '@') != NULL)
        return 3;

    return 0;
}

// to convert url in lowercase(to handel case insensitivity)
void to_lower(const char *url, char *l_url, int len)
{
    int i;
    for (i = 0; i < len - 1 && url[i] != '\0'; i++)
    {
        l_url[i] = (char)tolower((unsigned char)url[i]);
    }
    l_url[i] = '\0';
}

// to check suspicious word
int check_suspicious_word(const char *url)
{

    const char *word[] = {"login", "verify", "update", "confirm",
                          "secure", "account", "banking", "free",
                          "win", "gift", "prize", "urgent"};

    int len_word = sizeof(word) / sizeof(word[0]);
    char lower_url[MAX_URL_LEN];
    to_lower(url, lower_url, sizeof(lower_url));

    int score = 0;
    for (int i = 0; i < len_word; i++)
    {

        if (strstr(url, word[i]) != NULL)
            score += 1;
    }

    if (score > 3)
        score = 3;
    return score;
}

// to check hyphens in domain
int check_hyphen(char *url)
{
    char *pt = get_domain_pointer(url);

    while (*pt != '\0' && *pt != '/')
    {
        if (*pt == '-')
            return 2;
        pt++;
    }
    return 0;
}

// to check http not https
int check_http(const char *url)
{
    if (strncmp(url, "http://", 7) == 0)
        return 1;

    return 0;
}

// to calculate total phishing score
int phishing_score(char *url)
{
    int score = 0;

    score += check_ip_address(url);
    score += check_len(url);
    score += check_dot_hostname(url);
    score += check_symbol(url);
    score += check_hyphen(url);
    score += check_http(url);
    score += check_suspicious_word(url);

    return score;
}

int main()
{

    char url[MAX_URL_LEN];

    printf("\n*==* Simple URL Phishing Detector *==* \n");
    printf("Enter a URL: ");
    fgets(url, sizeof(url), stdin);

    newline_trim(url);

    int score = phishing_score(url);

    printf("\nURL: ");
    puts(url);
    printf("Phishing Score: %d\n", score);

    if (score >= 7)
        printf("Result: High-risk URL detected (Phishing suspected)!!\n\n");
    else if (score >= 4)
        printf("Result: High chance of phishing!\n\n");
    else
        printf("URL appears safe!\n\n");
    
    return 0;
}