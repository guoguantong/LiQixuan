#include <stdio.h>
#include <string.h>

void gadget_trap(void) {
    printf("Oops! You are trapped in a dead loop.\n");
    while (1) {
        /* infinite loop trap */
    }
}

int check_password(char *input) {
    if (input[0] == 'A') {
        if (input[1] == 'B') {
            gadget_trap();
        }
        if (input[1] == 'Z') {
            printf("Success! Flag is found.\n");
            return 1;
        }
    }
    printf("Wrong password!\n");
    return 0;
}

int main(void) {
    char password[10];
    printf("Enter password: ");
    scanf("%9s", password);
    check_password(password);
    return 0;
}
