
#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdio.h>
#include "pe_loader.h"
#include "vmp_decoder.h"

    int main(int argc, char **argv)
    {
        struct vmp_decoder *vmp_decoder1 = NULL;
        if (argc != 2)
        {
            printf("Usage: vmp_decoder [path]\n");
            return -1;
        }

        vmp_decoder1 = vmp_decoder_create(argv[1], 0);
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
