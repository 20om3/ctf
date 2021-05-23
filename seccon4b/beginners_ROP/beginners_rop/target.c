#include <stdio.h>
#include <unistd.h>

char *gets(char *s);

void vuln(){
    char str[0x100];
    gets(str);
    puts(str);
}

int main() {
    vuln();
}

__attribute__((constructor))
void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
}

