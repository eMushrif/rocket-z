gcc -o build/win_x64/img-sign.exe -L"C:\Program Files\OpenSSL-Win64\lib"  img-sign.c -O2 -I "C:\Program Files\OpenSSL-Win64\include" -llibcrypto
gcc -o build/win_x64/img-gen.exe -L"C:\Program Files\OpenSSL-Win64\lib"  ../pem/tiny-asn1.c ../pem/pem-decode.c ../header-gen.c img-gen.c -O2 -I "C:\Program Files\OpenSSL-Win64\include" -llibcrypto