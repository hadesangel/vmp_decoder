
#include <stdio.h>
#include <stdlib.h>

// 我的IDA上一直说找不到MS DIA SDK，但是我明明都安装了，vs2017, vs2008
// 最后实在没办法，因为release版本是可以看符号的，我在release版本中，关闭
// 了编译器优化
#pragma optimize( "", off )
int test_assign()
{
    int a;

    a = 0x1234;

    return a;
}
#pragma optimize( "", on )

int main()
{
    int a = 0;

    a = test_assign();

    printf("%d\n", a);

    return a + 1;
}