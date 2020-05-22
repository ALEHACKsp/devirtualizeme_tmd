#include "pch.h"

#include "cfg.hpp"
#include "x86_stream.hpp"
#include "x86_instruction.hpp"

// triton
#include <triton/api.hpp>
#include <triton/ast.hpp>
#include <triton/x86Specifications.hpp>
#pragma comment(lib, "triton.lib")

#define THEMIDA_CONTEXT_SIZE 0x00000200

struct VMInfo
{
	std::optional<triton::uint64> contextAddr, lockAddr, handlerTableAddr, bytecodeAddr;
	triton::uint64 stack_base;
	std::map<triton::uint64, triton::uint64> context_written, context_read;
} g_vm_info;

struct VMHandler
{
	std::vector<triton::uint8> context;
	triton::uint64 bytecode;
};

// triton helper
__inline triton::uint64 getStackPointerValue(triton::API& api)
{
	return api.getConcreteRegisterValue(api.getCpuInstance()->getStackPointer()).convert_to<triton::uint64>();
}
__inline triton::uint64 getProgramCounterValue(triton::API& api)
{
	return api.getConcreteRegisterValue(api.getCpuInstance()->getProgramCounter()).convert_to<triton::uint64>();
}
static std::set<triton::ast::SharedAbstractNode> _collect_variable_nodes(const triton::ast::SharedAbstractNode& node)
{
	// triton::ast::search but std::set instead
	std::set<triton::ast::SharedAbstractNode> result;
	if (!node)
		return result;

	std::stack<triton::ast::AbstractNode*>                worklist;
	std::unordered_set<const triton::ast::AbstractNode*>  visited;

	worklist.push(node.get());
	while (!worklist.empty()) {
		auto current = worklist.top();
		worklist.pop();

		// This means that node is already in work_stack and we will not need to convert it second time
		if (visited.find(current) != visited.end()) {
			continue;
		}

		visited.insert(current);
		if (current->getType() == triton::ast::VARIABLE_NODE)
			result.insert(current->shared_from_this());

		if (current->getType() == triton::ast::REFERENCE_NODE) {
			worklist.push(reinterpret_cast<triton::ast::ReferenceNode*>(current)->getSymbolicExpression()->getAst().get());
		}
		else {
			for (const auto& child : current->getChildren()) {
				worklist.push(child.get());
			}
		}
	}
	return result;
}


//
unsigned int apply_dead_store_elimination(std::list<std::shared_ptr<x86_instruction>>& instructions,
	std::map<x86_register, bool>& dead_registers, xed_uint32_t& dead_flags)
{
	unsigned int removed_bytes = 0;
	for (auto it = instructions.rbegin(); it != instructions.rend();)
	{
		const std::shared_ptr<x86_instruction> instr = *it;
		bool canRemove = true;
		std::vector<x86_register> readRegs, writtenRegs;
		xed_uint32_t read_flags = 0, written_flags = 0, alive_flags = ~dead_flags;
		instr->get_read_written_registers(&readRegs, &writtenRegs);

		// do not remove last? xd
		if (it == instructions.rbegin())
		{
			//goto update_dead_registers;
		}

		// check flags
		if (instr->uses_rflags())
		{
			read_flags = instr->get_read_flag_set()->flat;
			written_flags = instr->get_written_flag_set()->flat;
			if (alive_flags & written_flags)
			{
				// alive_flags being written by the instruction thus can't remove right?
				goto update_dead_registers;
			}
		}

		// check registers
		for (const x86_register& writtenRegister : writtenRegs)
		{
			if (writtenRegister.is_flag())
				continue;

			std::vector<x86_register> checks;
			if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR64)
			{
				checks.push_back(writtenRegister.get_gpr8_low());
				checks.push_back(writtenRegister.get_gpr8_high());
				checks.push_back(writtenRegister.get_gpr16());
				checks.push_back(writtenRegister.get_gpr32());
			}
			else if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR32)
			{
				checks.push_back(writtenRegister.get_gpr8_low());
				checks.push_back(writtenRegister.get_gpr8_high());
				checks.push_back(writtenRegister.get_gpr16());
			}
			else if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR16)
			{
				checks.push_back(writtenRegister.get_gpr8_low());
				checks.push_back(writtenRegister.get_gpr8_high());
			}
			checks.push_back(writtenRegister);

			for (const auto& check : checks)
			{
				if (!check.is_valid())
					continue;

				auto pair = dead_registers.find(check);
				if (pair == dead_registers.end() || !pair->second)
				{
					// Ž€‚ñ‚¾ƒŒƒWƒXƒ^‚Ìê‡‚Í‘±‚¯‚é
					goto update_dead_registers;
				}
			}
		}

		// check memory operand
		for (xed_uint_t j = 0, memops = instr->get_number_of_memory_operands(); j < memops; j++)
		{
			if (instr->is_mem_written(j))
			{
				// ƒƒ‚ƒŠ‚Ö‚Ì‘‚«ž‚Ý‚ª‚ ‚éê‡‚ÍÁ‚³‚È‚¢
				canRemove = false;
				break;
			}
		}

		// íœ‚·‚é
		if (canRemove)
		{
			removed_bytes += instr->get_length();
			//printf("remove ");
			//instr->print();

			// REMOVE NOW
			instructions.erase(--(it.base()));
			continue;
		}

		// update dead registers
	update_dead_registers:

		// check flags
		if (instr->uses_rflags())
		{
			dead_flags |= written_flags;	// add written flags
			dead_flags &= ~read_flags;		// and remove read flags
		}

		for (const x86_register& writtenRegister : writtenRegs)
		{
			if (writtenRegister.is_flag() || writtenRegister.get_class() == XED_REG_CLASS_IP)
				continue;

			if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR64)
			{
				dead_registers[writtenRegister.get_gpr8_low()] = true;
				dead_registers[writtenRegister.get_gpr8_high()] = true;
				dead_registers[writtenRegister.get_gpr16()] = true;
				dead_registers[writtenRegister.get_gpr32()] = true;
			}
			else if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR32)
			{
				dead_registers[writtenRegister.get_gpr8_low()] = true;
				dead_registers[writtenRegister.get_gpr8_high()] = true;
				dead_registers[writtenRegister.get_gpr16()] = true;
			}
			else if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR16)
			{
				dead_registers[writtenRegister.get_gpr8_low()] = true;
				dead_registers[writtenRegister.get_gpr8_high()] = true;
			}
			dead_registers[writtenRegister] = true;
		}
		for (const x86_register& readRegister : readRegs)
		{
			if (readRegister.is_flag() || readRegister.get_class() == XED_REG_CLASS_IP)
				continue;

			if (readRegister.get_gpr_class() == XED_REG_CLASS_GPR64)
			{
				dead_registers[readRegister.get_gpr8_low()] = false;
				dead_registers[readRegister.get_gpr8_high()] = false;
				dead_registers[readRegister.get_gpr16()] = false;
				dead_registers[readRegister.get_gpr32()] = false;
			}
			else if (readRegister.get_gpr_class() == XED_REG_CLASS_GPR32)
			{
				dead_registers[readRegister.get_gpr8_low()] = false;
				dead_registers[readRegister.get_gpr8_high()] = false;
				dead_registers[readRegister.get_gpr16()] = false;
			}
			else if (readRegister.get_gpr_class() == XED_REG_CLASS_GPR16)
			{
				dead_registers[readRegister.get_gpr8_low()] = false;
				dead_registers[readRegister.get_gpr8_high()] = false;
			}
			dead_registers[readRegister] = false;
		}

		++it;
	}

	return removed_bytes;
}
unsigned int peephole(std::list<std::shared_ptr<x86_instruction>>& instructions)
{
	// push pop
	for (auto it = instructions.begin(); it != instructions.end();)
	{
		const std::shared_ptr<x86_instruction> xed_instruction = *it;
		auto next = std::next(it);
		if (next == instructions.end())
			break;

		// remove
		if (xed_instruction->is_branch())
		{
			it = instructions.erase(it);
			continue;
		}
		else if (xed_instruction->get_iclass() == XED_ICLASS_MOV
			&& xed_instruction->get_operand(0).is_register()
			&& xed_instruction->get_operand(1).is_register()
			&& xed_instruction->get_register(XED_OPERAND_REG0) == xed_instruction->get_register(XED_OPERAND_REG1))
		{
			it = instructions.erase(it);
			continue;
		}

		// replace
		const std::shared_ptr<x86_instruction> xed_instruction2 = *next;
		if (xed_instruction->get_iclass() == XED_ICLASS_PUSH
			&& xed_instruction2->get_iclass() == XED_ICLASS_POP)
		{
			if (xed_instruction2->get_operand(0).is_register()
				&& xed_instruction2->get_register().get_largest_enclosing_register() != XED_REG_RSP)
			{
				// mov
				xed_instruction->encoder_set_iclass(XED_ICLASS_MOV);
				xed_instruction->encoder_set_operand_order(0, XED_OPERAND_REG0);
				xed_instruction->encoder_set_reg(XED_OPERAND_REG0, xed_instruction2->get_register());
				if (xed_instruction->get_operand(0).is_register())
				{
					xed_instruction->encoder_set_operand_order(1, XED_OPERAND_REG1);
					xed_instruction->encoder_set_reg(XED_OPERAND_REG1, xed_instruction->get_register());
				}
				else if (xed_instruction->get_operand(0).is_memory())
				{
					xed_instruction->encoder_set_operand_order(1, XED_OPERAND_MEM0);
					xed_instruction->encoder_set_mem0();
					xed_instruction->encoder_set_memory_operand_length(xed_instruction->get_memory_operand_length());
					xed_instruction->encoder_set_seg0(xed_instruction->get_segment_register());
					xed_instruction->encoder_set_base0(xed_instruction->get_base_register());
					xed_instruction->encoder_set_index(xed_instruction->get_index_register());
					xed_instruction->encoder_set_scale(xed_instruction->get_scale());
					if (xed_instruction->has_displacement())
					{
						xed_instruction->encoder_set_memory_displacement(
							xed_instruction->get_memory_displacement(), xed_instruction->get_memory_displacement_width());
					}
				}
				else if (xed_instruction->get_operand(0).is_immediate())
				{
					xed_instruction->encoder_set_operand_order(1, xed_instruction->get_operand(0).get_name());
					xed_instruction->encoder_set_uimm0(
						xed_instruction->get_unsigned_immediate(), xed_instruction->get_immediate_width());
				}
				else
					throw std::runtime_error("unknown operand type");

				xed_instruction->encode();
				it = instructions.erase(next);
				continue;
			}
		}
		else if (xed_instruction->get_iclass() == XED_ICLASS_PUSHAD
			&& xed_instruction2->get_iclass() == XED_ICLASS_POPAD)
		{
			it = instructions.erase(it);
			it = instructions.erase(next);
			continue;
		}

		++it;
	}

	return 0;
}
unsigned int deobfuscate_basic_block(std::list<std::shared_ptr<x86_instruction>>& instructions)
{
	for (int i = 0; i < 10; i++)
	{
		// all registers / memories should be considered 'ALIVE' when it enters basic block or when it leaves basic block
		std::map<x86_register, bool> dead_registers;
		xed_uint32_t dead_flags = 0;

		// for vmp handlers
		/*std::vector<x86_register> dead_ =
		{
			XED_REG_RAX, XED_REG_RCX, XED_REG_RDX
		};*/

		// for themida
		std::vector<x86_register> dead_ =
		{
			XED_REG_RAX, XED_REG_RCX, XED_REG_RDX, XED_REG_RBX, XED_REG_RSI, XED_REG_RDI
		};

		for (int i = 0; i < dead_.size(); i++)
		{
			const x86_register& reg = dead_[i];
			dead_registers[reg.get_gpr8_low()] = true;
			dead_registers[reg.get_gpr8_high()] = true;
			dead_registers[reg.get_gpr16()] = true;
			dead_registers[reg.get_gpr32()] = true;
			dead_registers[reg] = true;
		}

		// all flags must be dead
		dead_flags = 0xFFFFFFFF;

		unsigned int removed_bytes = apply_dead_store_elimination(instructions, dead_registers, dead_flags);
		peephole(instructions);
	}
	return 0;
}

//
bool jcc(xed_iclass_enum_t iclass, xed_flag_set_t* eflags, uint64_t rcx)
{
	switch (iclass)
	{
		case XED_ICLASS_JB:		return eflags->s.cf == 1;
		case XED_ICLASS_JBE:	return eflags->s.cf == 1 || eflags->s.zf == 1;
		case XED_ICLASS_JL:		return eflags->s.sf != eflags->s.of;
		case XED_ICLASS_JLE:	return eflags->s.zf == 1 || (eflags->s.sf != eflags->s.of);
		case XED_ICLASS_JNB:	return eflags->s.cf == 0;
		case XED_ICLASS_JNBE:	return eflags->s.cf == 0 && eflags->s.zf == 0;
		case XED_ICLASS_JNL:	return eflags->s.sf == eflags->s.of;
		case XED_ICLASS_JNLE:	return eflags->s.zf == 0 && eflags->s.sf == eflags->s.of;
		case XED_ICLASS_JNO:	return eflags->s.of == 0;
		case XED_ICLASS_JNP:	return eflags->s.pf == 0;
		case XED_ICLASS_JNS:	return eflags->s.sf == 0;
		case XED_ICLASS_JNZ:	return eflags->s.zf == 0;
		case XED_ICLASS_JO:		return eflags->s.of == 1;
		case XED_ICLASS_JP:		return eflags->s.pf == 1;
		case XED_ICLASS_JS:		return eflags->s.sf == 1;
		case XED_ICLASS_JZ:		return eflags->s.zf == 1;
		case XED_ICLASS_JCXZ:	return (rcx & 0x0000FFFF) == 0;
		case XED_ICLASS_JECXZ:	return (rcx & 0xFFFFFFFF) == 0;
		case XED_ICLASS_JRCXZ:	return rcx == 0;
		default:
		{
			std::stringstream ss;
			ss << "undefined COND_BR iclass: " << xed_iclass_enum_t2str(iclass);
			throw std::runtime_error(ss.str());
		}
	}
}




// vm handler analysis
static bool is_bytecode_address(const triton::ast::SharedAbstractNode& lea_ast)
{
	constexpr bool strict_check = true;
	if (strict_check)
	{
		// return true if lea_ast is constructed by bytecode
		const std::set<triton::ast::SharedAbstractNode> symvars = _collect_variable_nodes(lea_ast);
		if (symvars.empty())
			return false;

		for (auto it = symvars.begin(); it != symvars.end(); ++it)
		{
			const triton::ast::SharedAbstractNode& node = *it;
			const triton::engines::symbolic::SharedSymbolicVariable& symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable();
			if (symvar->getAlias() != "bytecode")
				return false;
		}
	}

	return true;
}
static void vm_handler_mem_read(triton::API& api, const triton::arch::MemoryAccess& mem)
{
	// bytecode, stack, context(static), context(dynamic), deref
	const triton::uint64 runtime_address = mem.getAddress();
	const triton::uint64 current_stack_pointer = getStackPointerValue(api);
	if (current_stack_pointer <= runtime_address && runtime_address < g_vm_info.stack_base)
	{
		// valid local variable
		return;
	}

	triton::ast::SharedAbstractNode lea_ast = mem.getLeaAst();
	if (runtime_address == g_vm_info.bytecodeAddr)
	{
		std::cout << "r bytecode address\n";
	}
	else if (g_vm_info.contextAddr <= runtime_address && runtime_address < (g_vm_info.contextAddr.value() + 0x200))
	{
		const triton::uint64 offset = runtime_address - g_vm_info.contextAddr.value();
		if (!api.isMemoryTainted(mem))
		{
			// static read
			std::cout << "r static [BP+0x" << std::hex << offset << "]\n";
		}
		else
		{
			// dynamic read
			std::cout << "r dynamic [BP+0x" << std::hex << offset << "]\n";
			std::cout << api.processSimplification(api.getMemoryAst(mem), 1) << "\n";
		}
	}
	else if (is_bytecode_address(lea_ast))
	{
		// ptr?
		std::cout << "r bytecode 0x" << std::hex << runtime_address << " " << api.getConcreteMemoryValue(mem) << "\n";
		api.taintMemory(mem);
	}
	else if (api.isConcreteMemoryValueDefined(mem))
	{
		// ptr?
		std::cout << "r unknown 0x" << std::hex << runtime_address << " " << api.getConcreteMemoryValue(mem) << "\n";
	}
	else
	{
		std::cout << "r unknown 0x" << std::hex << runtime_address << "\n";
	}
}
static void vm_handler_mem_write(triton::API& api, const triton::arch::MemoryAccess& mem, const triton::uint512& value)
{
	// lock, bytecode, context(static), context(dynamic), ptr
	const triton::uint64 runtime_address = mem.getAddress();
	const triton::uint64 current_stack_pointer = getStackPointerValue(api);
	if (current_stack_pointer <= runtime_address && runtime_address < g_vm_info.stack_base)
	{
		// valid local variable
		return;
	}

	triton::ast::SharedAbstractNode lea_ast = mem.getLeaAst();
	if (runtime_address == g_vm_info.bytecodeAddr)
	{
		std::cout << "w bytecode=0x" << std::hex << value << "\n";
	}
	else if (runtime_address == g_vm_info.lockAddr)
	{
		std::cout << "w lock=0x" << std::hex << value << "\n";
	}
	else if (g_vm_info.contextAddr <= runtime_address && runtime_address < (g_vm_info.contextAddr.value() + 0x200))
	{
		const triton::uint64 offset = runtime_address - g_vm_info.contextAddr.value();
		if (!api.isMemoryTainted(mem))
		{
			// static write
			std::cout << "w static [BP+0x" << std::hex << offset << "]=0x" << value << "\n";
		}
		else
		{
			// dynamic write
			std::cout << "w dynamic [BP+0x" << std::hex << offset << "]=0x" << value << "\n";
		}
	}
	else
	{
		// ptr?
	}
}
static void run_handler(x86_stream& stream, uint64_t address, VMHandler* handler)
{
	auto triton_api = std::make_shared<triton::API>();
	triton_api->setArchitecture(triton::arch::ARCH_X86);

	{
		// set mem
		/*std::vector<triton::uint8> v;
		constexpr int size = 0x00DCF000 - 0x00C00000;
		v.resize(size);
		stream.seek(0x00C00000);
		stream.read(&v[0], size);
		triton_api->setConcreteMemoryAreaValue(0x00C00000, v);*/

		// set context
		triton_api->setConcreteMemoryAreaValue(g_vm_info.contextAddr.value(), handler->context);
	}

	// push/pop gud
	triton_api->setMode(triton::modes::ALIGNED_MEMORY, true);

	// apply simple simplification (ex: A ^ 0 -> A)
	triton_api->setMode(triton::modes::AST_OPTIMIZATIONS, true);

	triton_api->setMode(triton::modes::TAINT_THROUGH_POINTERS, true);

	triton_api->setAstRepresentationMode(triton::ast::representations::PYTHON_REPRESENTATION);

	// symbolize themida context
	//triton_api->setConcreteMemoryAreaValue(g_vm_info.contextAddr.value(), handler->context);
	//triton_api->setConcreteMemoryValue(triton::arch::MemoryAccess(g_vm_info.bytecodeAddr.value(), 4), handler->bytecode);
	triton_api->symbolizeMemory(triton::arch::MemoryAccess(g_vm_info.bytecodeAddr.value(), 4), "bytecode");
	triton_api->symbolizeMemory(triton::arch::MemoryAccess(g_vm_info.handlerTableAddr.value(), 4), "handlerTable");

	// set stack base so it won't mess up
	g_vm_info.stack_base = 0x10001000;
	triton_api->setConcreteRegisterValue(triton_api->getParentRegister(triton::arch::ID_REG_X86_BP), g_vm_info.contextAddr.value());
	triton_api->setConcreteRegisterValue(triton_api->getCpuInstance()->getStackPointer(), g_vm_info.stack_base);

	// symbolize everything now
	auto _work = [triton_api](const triton::arch::Register& reg)
	{
		auto symvar = triton_api->symbolizeRegister(reg);
		symvar->setAlias(reg.getName());
	};
	_work(triton_api->getParentRegister(triton::arch::ID_REG_X86_BP));



	triton_api->addCallback(vm_handler_mem_read);
	triton_api->addCallback(vm_handler_mem_write);
	for (;;)
	{
		stream.seek(address);
		std::shared_ptr<x86_instruction> xed_instruction = stream.next();
		const std::vector<xed_uint8_t> bytes = xed_instruction->get_bytes();

		// triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(xed_instruction->get_addr());
		if (!triton_api->processing(triton_instruction))
		{
			throw std::runtime_error("triton processing failed");
		}

		triton_instruction.getWrittenRegisters();

		// jmp / jcc / call / ret / loop / loopcc
		if (triton_instruction.isControlFlow())
		{
			auto ast = triton_api->getRegisterAst(triton_api->getCpuInstance()->getProgramCounter());
			if (triton_api->isRegisterTainted(triton_api->getCpuInstance()->getProgramCounter())
				&& xed_instruction->get_category() != XED_CATEGORY_COND_BR)
			{
				std::cout << "\tjmp toward " << triton::ast::unroll(ast) << std::endl;
				break;
			}
		}
		else
		{
			std::cout << "\t" << triton_instruction << "\n";
		}

		address = getProgramCounterValue(*triton_api);
	}



}



// vm enter analysis
static void vm_enter_mem_read(triton::API& api, const triton::arch::MemoryAccess& mem)
{
	const triton::uint64 runtime_address = mem.getAddress();
	const triton::uint64 current_stack_pointer = getStackPointerValue(api);
	if (current_stack_pointer <= runtime_address && runtime_address < g_vm_info.stack_base)
	{
		// valid local variable
		return;
	}

	if (!g_vm_info.contextAddr.has_value())
	{
		// should be lock cmpxchg
		const triton::arch::Register& base_reg = mem.getConstBaseRegister();
		if (base_reg == api.getParentRegister(triton::arch::ID_REG_X86_BP))
		{
			g_vm_info.contextAddr = api.getConcreteRegisterValue(base_reg).convert_to<triton::uint64>();
		}
		else
		{
			throw std::runtime_error("unexpected memory read");
		}
		return;
	}

	// should check leaast tbh
	if (g_vm_info.contextAddr <= runtime_address && runtime_address < (g_vm_info.contextAddr.value() + 0x200))
	{
		triton::uint64 val = 0;
		if (!api.isConcreteMemoryValueDefined(mem))
		{
			// read from stream
			printf("\tread-first-time-context: %016llX\n", runtime_address);
			throw std::runtime_error("context is not concreated");
		}
		else
		{
			// read written memory
			val = api.getConcreteMemoryValue(mem).convert_to<triton::uint64>();
			printf("\tread-context: %016llX %016llX\n", runtime_address, val);

			char _alias[256];
			sprintf_s(_alias, 256, "read_%016llX_%d", runtime_address, mem.getSize());
			api.symbolizeMemory(mem, _alias);
		}

		g_vm_info.context_read[runtime_address] = val;
	}
	else
	{
		//std::cout << triton::ast::unroll(mem.getLeaAst()) << "\n";

		// probably handler
		char _alias[256];
		sprintf_s(_alias, 256, "read_%016llX_%d", runtime_address, mem.getSize());
		api.symbolizeMemory(mem, _alias);
	}
}
static void vm_enter_mem_write(triton::API& api, const triton::arch::MemoryAccess& mem, const triton::uint512& value)
{
	const triton::uint64 runtime_address = mem.getAddress();
	const triton::uint64 current_stack_pointer = getStackPointerValue(api);
	if (current_stack_pointer <= runtime_address && runtime_address < g_vm_info.stack_base)
	{
		// valid local variable
		return;
	}

	if (!g_vm_info.contextAddr.has_value())
	{
		throw std::runtime_error("unexpected memory write");
	}

	// should check leaast tbh
	if (g_vm_info.contextAddr <= runtime_address && runtime_address < (g_vm_info.contextAddr.value() + 0x200))
	{
		g_vm_info.context_written[runtime_address] = value.convert_to<triton::uint64>();
		printf("\twrite-context: %016llX=%016llX\n", runtime_address, value.convert_to<triton::uint64>());
	}
	else
	{
		// probably baserelocation fix
	}
}
static std::vector<triton::uint8> run_enter(x86_stream& stream, uint64_t address)
{
	auto triton_api = std::make_shared<triton::API>();
	triton_api->setArchitecture(triton::arch::ARCH_X86);

	// push/pop gud
	triton_api->setMode(triton::modes::ALIGNED_MEMORY, true);

	// apply simple simplification (ex: A ^ 0 -> A)
	triton_api->setMode(triton::modes::AST_OPTIMIZATIONS, true);

	triton_api->setAstRepresentationMode(triton::ast::representations::PYTHON_REPRESENTATION);
	triton_api->addCallback(vm_enter_mem_read);
	triton_api->addCallback(vm_enter_mem_write);

	g_vm_info.stack_base = 0x10001000;
	triton_api->setConcreteRegisterValue(triton_api->getCpuInstance()->getStackPointer(), g_vm_info.stack_base);

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

	std::list< std::shared_ptr<x86_instruction>> xed_instruction_list;
	for (;;)
	{
		// read instruction
		stream.seek(address);
		std::shared_ptr<x86_instruction> xed_instruction = stream.next();
		const std::vector<xed_uint8_t> bytes = xed_instruction->get_bytes();
		xed_instruction_list.push_back(xed_instruction);

		// triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(xed_instruction->get_addr());
		if (!triton_api->processing(triton_instruction))
		{
			throw std::runtime_error("triton processing failed");
		}

		//std::cout << triton_instruction << "\n";

		// lock cmpxchg dword ptr [ebp+ebx*1], ecx
		if (triton_instruction.getType() == triton::arch::x86::ID_INS_CMPXCHG
			&& triton_instruction.getPrefix() == triton::arch::x86::ID_PREFIX_LOCK)
		{
			const triton::arch::Register bp_register = triton_api->getParentRegister(triton::arch::ID_REG_X86_BP);
			for (const std::pair<triton::arch::MemoryAccess, triton::ast::SharedAbstractNode>& pair : triton_instruction.getLoadAccess())
			{
				const triton::arch::MemoryAccess& mem = pair.first;
				const triton::ast::SharedAbstractNode& node = pair.second;
				if (mem.getConstBaseRegister() != bp_register)
				{
					throw std::runtime_error("base register for lock cmpxchg is not BP");
				}

				g_vm_info.contextAddr = triton_api->getConcreteRegisterValue(bp_register).convert_to<triton::uint64>();
				g_vm_info.lockAddr = mem.getAddress();

				std::vector<triton::uint8> v;
				v.resize(THEMIDA_CONTEXT_SIZE);
				stream.seek(g_vm_info.contextAddr.value());
				stream.read(&v[0], THEMIDA_CONTEXT_SIZE);

				triton_api->removeCallback(vm_enter_mem_write);
				triton_api->setConcreteMemoryAreaValue(g_vm_info.contextAddr.value(), v);
				triton_api->addCallback(vm_enter_mem_write);
			}
		}
		else if (triton_instruction.getType() == triton::arch::x86::ID_INS_PUSHFD)
		{
			auto stack = triton_api->getCpuInstance()->getStackPointer();
			triton::arch::MemoryAccess mem(getStackPointerValue(*triton_api), stack.getSize());
			triton_api->symbolizeMemory(mem, "eflags");
		}

		if (triton_instruction.isControlFlow() && triton_instruction.operands.size() == 1)
		{
			if (triton_instruction.operands[0].getType() == triton::arch::OP_IMM)
			{
				// jmp x / jcc x / ret x?
			}
			else
			{
				// jmp reg/mem
				auto ast = triton_api->getRegisterAst(triton_api->getCpuInstance()->getProgramCounter());
				std::cout << "\tjmp toward " << triton::ast::unroll(ast) << std::endl;
				break;
			}
		}

		address = getProgramCounterValue(*triton_api);
	}

	// DEBUG
	for (const auto& pair : g_vm_info.context_read)
	{
		if (g_vm_info.context_written.find(pair.first) == g_vm_info.context_written.end())
		{
			// readonly
			if (g_vm_info.handlerTableAddr.has_value())
			{
				throw std::runtime_error("can't determine handler table address");
			}
			g_vm_info.handlerTableAddr = pair.first;
			std::cout << std::hex << pair.first << std::endl;
		}
	}
	if (!g_vm_info.handlerTableAddr.has_value())
	{
		g_vm_info.handlerTableAddr = 0x05077D5;
		//throw std::runtime_error("can't determine handler table address");
	}

	// important
	std::cout << "ContextAddr: 0x" << std::hex << g_vm_info.contextAddr.value() << "\n";
	std::cout << "LockAddr: 0x" << std::hex << g_vm_info.lockAddr.value() << "\n";
	std::cout << "HandlerTableAddr: 0x" << std::hex << g_vm_info.handlerTableAddr.value() << "\n";
	std::cout << "HandlerAddr: 0x" << std::hex << getProgramCounterValue(*triton_api) << "\n";

	// show written
	std::cout << "Themida Context:" << "\n";
	const triton::arch::Register bp_register = triton_api->getParentRegister(triton::arch::ID_REG_X86_BP);
	for (const auto& pair : g_vm_info.context_written)
	{
		const triton::uint64 _offset = pair.first - g_vm_info.contextAddr.value();
		std::cout << "\t[" << bp_register.getName() << "+0x" << std::hex << _offset << "]=0x" << pair.second << "\n";

		// how do u determine bytecode lol
		if (_offset == 0x81)
		{
			g_vm_info.bytecodeAddr = pair.first;
		}
	}

	// check stack
	std::cout << "VM Enter:" << "\n";
	const triton::arch::Register& stack = triton_api->getCpuInstance()->getStackPointer();
	const triton::uint32 stack_addr_size = stack.getSize();
	const triton::uint64 modified_sp = triton_api->getConcreteRegisterValue(stack).convert_to<triton::uint64>();
	const triton::uint64 var_length = (g_vm_info.stack_base - modified_sp) / stack_addr_size;
	for (triton::uint64 i = 0; i < var_length; i++)
	{
		triton::ast::SharedAbstractNode mem_ast = triton_api->getMemoryAst(
			triton::arch::MemoryAccess(g_vm_info.stack_base - (i * stack_addr_size) - stack_addr_size, stack_addr_size));
		triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(mem_ast, true);
		if (simplified->getType() == triton::ast::VARIABLE_NODE)
		{
			const triton::engines::symbolic::SharedSymbolicVariable& symvar =
				std::dynamic_pointer_cast<triton::ast::VariableNode>(simplified)->getSymbolicVariable();
			std::cout << "\tpush " << simplified << std::endl;

		}
		else
		{
			//const triton::uint64 val = simplified->evaluate().convert_to<triton::uint64>();
			std::cout << "\tpush " << simplified << std::endl;
		}
	}

	return triton_api->getConcreteMemoryAreaValue(g_vm_info.contextAddr.value(), THEMIDA_CONTEXT_SIZE, false);
}

void deob(x86_stream& stream, uint64_t address)
{
	auto v = run_enter(stream, address);

	VMHandler ctx;
	ctx.context = v;
	run_handler(stream, 0x00A4D4DA, &ctx);
}