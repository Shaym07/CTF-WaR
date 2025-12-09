// Strings Hunt Challenge - Source Code
// Compile: gcc -o strings_challenge strings_challenge.c

#include <stdio.h>
#include <string.h>

// The flag is hidden in the binary as a string
const char* secret_flag = "WOW{str1ngs_4r3_us3ful}";
const char* decoy1 = "This is not the flag";
const char* decoy2 = "Try harder!";

int main() {
    char input[100];
    printf("Enter the password: ");
    scanf("%99s", input);

    if (strcmp(input, "hunter2") == 0) {
        printf("Access granted!\n");
        printf("But the real flag is hidden... use 'strings' command!\n");
    } else {
        printf("Wrong password!\n");
    }

    return 0;
}

// Hint: Run 'strings strings_challenge | grep WOW'
