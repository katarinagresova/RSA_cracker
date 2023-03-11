all: rsa.h
	g++ rsa.cpp -std=c++0x -o kry -lgmpxx -lgmp