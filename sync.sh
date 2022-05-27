#/bin/bash

# make urts
make -C ./psw/urts/linux
# move headers
cp ./common/inc/*.h ./sgxsdk/include/
# move libary
cp ./psw/urts/linux/*.so /lib/
cp ./psw/urts/linux/*.so ./sgxsdk/lib64/
