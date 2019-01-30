

#ifndef __vmp_decoder__
#define __vmp_decoder__

struct vmp_decoder;

struct vmp_decoder *vmp_decoder_create(char *filename, DWORD vmp_start_rva, int dump_pe);
void vmp_decoder_destroy(struct vmp_decoder *decoder);
int vmp_decoder_run(struct vmp_decoder *decoder);


#endif