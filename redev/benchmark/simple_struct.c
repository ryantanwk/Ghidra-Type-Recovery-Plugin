#include <stdio.h>

struct simple_st{
    int m;
    int n;
};

int main(int argc, char* argv[])
{
    struct simple_st s = {10, 20};
    int sum;

    sum = s.m + s.n;
    return sum;
}
