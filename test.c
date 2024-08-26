#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

typedef struct t
{
    char* str;
} t;

void test(t *pt)
{
    pt->str = "test";
}

int main() {
    t abc;
    printf(abc.str);
    return 0;
}