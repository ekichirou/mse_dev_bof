# mse_dev_bof

This is a proof of concept demonstrating an Edge cookie extraction technique using remote debugging through a BOF.
**NOTE:** The BOF opens a remote debugging port on `7005`.

## Compilation
1. Compile using the following command: `x86_64-w64-mingw32-gcc -c mse_dev_bof.c -o mse_dev_bof.o`

## Inspiration

Inspired by:  
<https://specterops.io/blog/2020/12/17/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port/>
