
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

        // 
        //setbuf(stdout, NULL);

        vmp_decoder1 = vmp_decoder_create(cmd_mod.filename, 0, cmd_mod.dump_pe);
        if (NULL == vmp_decoder1)
        {
            printf("main() failed with vmp_decoder_create(). %s:%d\n", __FILE__, __LINE__);
            return -1;
        }

        if (vmp_decoder_run(vmp_decoder1))
        {
            printf("main() failed with vmp_decoder_run(). %s:%d", __FILE__, __LINE__);
        }

        vmp_decoder_destroy(vmp_decoder1);

        return 0;
    }

#ifdef __cplusplus
}
#endif
