#pragma once

#define LOG(message) std::cout << message;

#define Error(stage, code)\
	if (code != 0){\
		LOG(stage << " fail\n");\
		LOG("Error code: " << std::hex << code << "\n");\
		exit(-1);\
	}else{\
		LOG(stage << " OK\n");\
	}\

#define FOR(size) for(int i = 0; i < size; i++)