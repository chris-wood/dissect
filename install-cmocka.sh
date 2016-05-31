#!/bin/bash
wget https://cmocka.org/files/1.0/cmocka-1.0.0.tar.xz
tar -xfz cmocka-1.0.0.tar.xz
cd cmocka-1.0.0
./configure && make && make install