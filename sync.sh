#/bin/bash

# move headers
cp ./common/inc/*.h ./sgxsdk/include/
# make urts
make -C ./psw/urts/linux DEBUG=1
make -C ./psw/enclave_common/ DEBUG=1
# move libary
cp ./psw/enclave_common/*.so /lib/
cp ./psw/enclave_common/*.so ./sgxsdk/lib64/
cp ./psw/urts/linux/*.so /lib/
cp ./psw/urts/linux/*.so ./sgxsdk/lib64/
