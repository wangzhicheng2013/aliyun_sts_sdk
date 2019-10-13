g++ -std=c++11 -g -o Test test.cpp -I ./ -I ./include -L ./lib -lcurl -lcrypto -ldl -ljsoncpp
#valgrind --tool=memcheck --leak-check=full ./Test
