#pragma once

#include "x86_stream.hpp"

struct BasicBlock
{
	// first instruction that starts basic block
	triton::uint64 leader;

	std::list<std::shared_ptr<x86_instruction>> instructions;

	// when last instruction can't follow
	bool terminator;

	std::shared_ptr<BasicBlock> next_basic_block, target_basic_block;
};

extern void make_cfg(x86_stream& stream, uint64_t address);