#pragma once

#define LOG(message) std::cout << message;

#define TITLE(message) LOG("\n\t>> " << message << "...\n\n")

#define ERROR(stage, code)\
	if (code != 0){\
		LOG(stage << " fail\n");\
		LOG("Error code: " << std::hex << code << "\n");\
		exit(-1);\
	}else{\
		LOG(stage << ": OK\n\n");\
	}\

#define FOR(size) for(int i = 0; i < size; i++)