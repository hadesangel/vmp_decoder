
#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_loader.h"
#include "vmp_decoder.h"

    struct vmp_cmd_params
    {
        int dump_pe;
        char filename[128];
        char log_filename[128];
    };

    int vmp_help(void)
    {
        printf("Usage: vmp_decoder [-dump_pe] [-help] filename\n");
        return 0;
    }

    int vmp_cmd_parse(struct vmp_cmd_params *cmd_mod, int argc, char **argv)
    {
        int i;

        for (i = 1; i < argc; i++)
        {
            if (!strcmp(argv[i], "-dump_pe"))
            {
                cmd_mod->dump_pe = 1;
            }
            else if (!strcmp(argv[i], "-help"))
            {
                vmp_help();
                return 1;
            }
            else
            {
                strcpy(cmd_mod->filename, argv[i]);
            }
        }

        if (!cmd_mod->filename[0])
        {
            vmp_help();
            return 1;
        }

        return 0;
    }

    int main(int argc, char **argv)
    {
        struct vmp_decoder *vmp_decoder1 = NULL;
        struct vmp_cmd_params cmd_mod = { 0 };
        if (vmp_cmd_parse (&cmd_mod, argc, argv))
        {
            return 0;
        }

        // 我在调试的时候碰到一个问题，就是假如在cmd里直接运行把调试信息直接输出到屏幕上
        // 虽然可以运行完，然后因为错误信息太多需要很长时间才能结束，但是假如重定向到
        // 文件里，可以很快运行完，不过因为printf是有缓冲区的，即使追加了\n，但是在重定
        // 向到管道里时可能因为管道的BUF没有立即清空，导致假如把信息往管道里写，那么在
        // 系统崩溃时这个日志输出可能不完全
        // 现在有2种解决思路
        //      1. setbuf(stdout, NULL)， 把printf的输出缓冲置0，这样信息可以即使刷到标准
        // 输出,但是这样会让程序性能降低，经过测试，性能只有大约以前的1/5左右
        //      2. 在程序内部把printf重定向到文件里面去，但是经过测试发现，freopen过以后
        // 依然无法解决崩溃时的信息漏掉的问题，采用了try, catch的方式，捕获到异常后，强行
        // 进行fflush
        // 我们采用第2种
        freopen("vmp.log", "w", stdout);

        vmp_decoder1 = vmp_decoder_create(cmd_mod.filename, 0, cmd_mod.dump_pe);
        if (NULL == vmp_decoder1)
        {
            printf("main() failed with vmp_decoder_create(). %s:%d\n", __FILE__, __LINE__);
            return -1;
        }

        __try
        { 
            if (vmp_decoder_run(vmp_decoder1))
            {
                printf("main() failed with vmp_decoder_run(). %s:%d", __FILE__, __LINE__);
            }
        }
        __finally
        {
            fflush(stdout);
        }


        vmp_decoder_destroy(vmp_decoder1);

        return 0;
    }

#ifdef __cplusplus
}
#endif
