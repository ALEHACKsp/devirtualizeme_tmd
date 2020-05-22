#include "pch.h"

#include "cfg.hpp"
#include "x86_stream.hpp"
#include "x86_instruction.hpp"
#include "triton.hpp"

//
static triton::uint64 g_cfg_stack = 0;
static std::map<triton::usize, triton::uint64> g_unknown;

// cfg
static void cfg_mem_read(triton::API& api, const triton::arch::MemoryAccess& mem)
{
	const triton::uint64 runtime_address = mem.getAddress();
	const triton::uint64 current_stack_pointer = getStackPointerValue(&api);
	if (current_stack_pointer <= runtime_address && runtime_address <= g_cfg_stack)
	{
		// valid local variable
		return;
	}

	// unknown
	char _alias[256];
	sprintf_s(_alias, 256, "read_%llx_%d", runtime_address, mem.getSize());
	auto symvar = api.symbolizeMemory(mem, _alias);
	g_unknown.insert(std::make_pair(symvar->getId(), runtime_address));
}
static void cfg_mem_write(triton::API& api, const triton::arch::MemoryAccess& mem, const triton::uint512& value)
{
}
static void explore(x86_stream& stream, uint64_t address, std::multiset<triton::uint64>& leaders, std::map<triton::uint64, std::shared_ptr<x86_instruction>>& visit)
{
	auto triton_api = std::make_shared<triton::API>();
	triton_api->setArchitecture(triton::arch::ARCH_X86);

	// track even when not symbolized
	triton_api->setMode(triton::modes::PC_TRACKING_SYMBOLIC, false);

	// push/pop gud
	triton_api->setMode(triton::modes::ALIGNED_MEMORY, true);

	// apply simple simplification (ex: A ^ 0 -> A)
	triton_api->setMode(triton::modes::AST_OPTIMIZATIONS, true);
	triton_api->setMode(triton::modes::CONSTANT_FOLDING, true);
	triton_api->setMode(triton::modes::ONLY_ON_SYMBOLIZED, true);

	triton_api->setAstRepresentationMode(triton::ast::representations::PYTHON_REPRESENTATION);
	triton_api->addCallback(cfg_mem_read);
	triton_api->addCallback(cfg_mem_write);

	g_cfg_stack = 0x1001000;
	triton_api->setConcreteRegisterValue(triton_api->getCpuInstance()->getStackPointer(), g_cfg_stack);

	// symbolize everything now
	auto _symbolizeRegister = [triton_api](const triton::arch::Register& reg)
	{
		auto symvar = triton_api->symbolizeRegister(reg);
		symvar->setAlias(reg.getName());
	};
	_symbolizeRegister(triton_api->registers.x86_eax);
	_symbolizeRegister(triton_api->registers.x86_ebx);
	_symbolizeRegister(triton_api->registers.x86_ecx);
	_symbolizeRegister(triton_api->registers.x86_edx);
	_symbolizeRegister(triton_api->registers.x86_esi);
	_symbolizeRegister(triton_api->registers.x86_edi);
	_symbolizeRegister(triton_api->registers.x86_ebp);

	for (;;)
	{
		// read instruction
		stream.seek(address);
		std::shared_ptr<x86_instruction> xed_instruction = stream.next();
		const std::vector<xed_uint8_t> bytes = xed_instruction->get_bytes();
		visit.insert(std::make_pair(address, xed_instruction));

		// triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(xed_instruction->get_addr());
		if (!triton_api->processing(triton_instruction))
		{
			throw std::runtime_error("triton processing failed");
		}

		bool direct_jmp = triton_instruction.getType() == triton::arch::x86::ID_INS_JMP && triton_instruction.operands[0].getType() == triton::arch::OP_IMM;
		if (!direct_jmp)
		{
			std::cout << triton_instruction << "\n";
		}
		if (!triton_instruction.isControlFlow()
			|| triton_instruction.getType() == triton::arch::x86::ID_INS_CALL
			|| direct_jmp)
		{
			address = getProgramCounterValue(triton_api.get());
			continue;
		}

		const auto& pathConstraints = triton_api->getPathConstraints();
		if (pathConstraints.empty())
			throw std::runtime_error("getPathConstraints");

		const auto& pathConstraint = pathConstraints.back();

		// <flag, source, dst, pc>
		const auto& branches = pathConstraint.getBranchConstraints();
		for (auto it = branches.begin(); it != branches.end(); it++)
		{
			if (std::get<0>(*it) == false)
			{
				if (triton_api->isSat(std::get<3>(*it)))
				{
					// dst
					leaders.insert(std::get<2>(*it));
					std::cout << triton_instruction << "\n";
					std::cout << "real jcc\n";
					//getchar();
				}
				else
				{
					// possibly opaque predicate (or loop)
					//std::cout << "possibly opaque predicate\n";
					//getchar();
				}
			}
		}
		triton_api->clearPathConstraints();

		address = getProgramCounterValue(triton_api.get());
	}
}
static std::vector<triton::uint8> _make_cfg(x86_stream& stream, uint64_t address)
{
	std::multiset<triton::uint64> leaders;
	std::map<triton::uint64, std::shared_ptr<x86_instruction>> visit;
	explore(stream, address, leaders, visit);

	for (const triton::uint64 leader : leaders)
	{
		if (visit.find(leader) == visit.end())
		{
			// 
			explore(stream, leader, leaders, visit);
		}
	}
}




void make_cfg(x86_stream& stream, uint64_t address)
{
	address = 0x007A0F92;
	//address = 0xb8b6dc;
	//address = 0x0040101C;
	_make_cfg(stream, address);
}