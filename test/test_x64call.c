#include <stdio.h>
#include <string.h> 

int add(int a1, int a2) {
    int res = a1 + a2;
    printf(" result = %d\n", res);
    return res;
}

int main(int argc, char** argv) 
{
    char buffer[0x100];

    printf("add_addr = %p\n", add);

    while (1) {
        printf("> ");
        if (gets_s(buffer, 0x100)) {

            if (!strcmp(buffer, "exit")) {
                return 0;
            }

            char* s1 = strtok(buffer, ",");
            char* s2 = strtok(NULL, ",");
            if (!s1 || !s2) {
                continue;
            }
            int a1 = atoi(s1);
            int a2 = atoi(s2);

            add(a1,a2);
        }
    }
    return 0;
}