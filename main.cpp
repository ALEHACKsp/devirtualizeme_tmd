#include "pch.h"

#include "process_stream.hpp"
#include "x86_instruction.hpp"
#include "cfg.hpp"

void routine()
{
	process_stream stream(false);
	if (!stream.open("devirtualizeme_tmd_2.4.6.0_tiger32.exe"))
		throw std::runtime_error("stream.open failed.");

	// 1: 0x0040CA5A
	// 2: 0x0040C97A
	// 3: 0x0040C89A
	make_cfg(stream, 0x0040CA5A);
}

void fish32()
{
	process_stream stream(false);
	if (!stream.open("devirtualizeme_tmd_2.4.6.0_fish32.exe"))
		throw std::runtime_error("stream.open failed.");

	// 00C50BAB - jmp dword ptr [eax]
	// 0x00A4D4DA <- some handler
	//deob(stream, 0x00A4D4DA);
	//deob(stream, 0x00870D05);
	//deob(stream, 0x005BEE39);
	//deob(stream, 0x005C2D73);
	//deob(stream, 0x007A0F92);
	make_cfg(stream, 0x0040C89A);
}

int main(int argc, char* argv[])
{
	// Once, before using Intel XED, you must call xed_tables_init() to initialize the tables Intel XED uses for encoding and decoding:
	xed_tables_init();

	auto start = std::chrono::steady_clock::now();

	try
	{
		fish32();
	}
	catch (const std::exception& ex)
	{
		std::cout << ex.what() << std::endl;
	}

	auto end = std::chrono::steady_clock::now();
	auto elapse = end - start;
	const double elapse_ms = std::chrono::duration<double, std::milli>(elapse).count();
	std::cout << elapse_ms << " ms.";

	return 0;
}