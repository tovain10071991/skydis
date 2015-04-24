#include <udis86.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdio.h>
#include <stdlib.h>	//EXIT_FAILURE
#include <unistd.h>

int main(int argc, char** argv)
{
	FILE* input_udis = fopen("//bin//ls", "r");
	FILE* output = fopen("ls.dis", "w");

	int input_elf = open("//bin//ls", O_RDONLY, 0);

	ud_t ud_obj;
    ud_init(&ud_obj);

	Elf* elf;
	GElf_Ehdr ehdr;
	Elf_Data* data;
	GElf_Shdr shdr;
	Elf_Scn* scn=NULL;

	elf_version(EV_CURRENT);
	elf = elf_begin(input_elf, ELF_C_READ, NULL);

	// read entry at first
	gelf_getehdr(elf, &ehdr);
	Elf32_Addr entry = ehdr.e_entry;
	printf("%x\n", entry);

	//find .text section
	while((scn=elf_nextscn(elf, scn))!=NULL)
	{
		gelf_getshdr(scn, &shdr);
		if(entry>=shdr.sh_addr&&entry<=shdr.sh_addr+shdr.sh_size)
			break;
	}
	if(scn==NULL)
		exit(-1);
	//find enrty's offset in file
	size_t offset = entry-(shdr.sh_addr-shdr.sh_offset);

    ud_set_input_file(&ud_obj, input_udis);
    ud_set_mode(&ud_obj, 32);
    ud_set_syntax(&ud_obj, UD_SYN_ATT);
	ud_set_pc(&ud_obj, entry);
	ud_input_skip(&ud_obj, offset);

	fprintf(output, "ADDR\tTYPE\tHEX\tINS\n");

    while (ud_disassemble(&ud_obj)) {
        fprintf(output, "0x%llx\t%-20s\t%s\n", ud_insn_off(&ud_obj), ud_insn_hex(&ud_obj), ud_insn_asm(&ud_obj));
    }

	elf_end(elf);
	close(input_elf);
	fcloseall();
    return 0;
}
