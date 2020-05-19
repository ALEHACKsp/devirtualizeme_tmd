#include "pch.h"

#include "x86_instruction.hpp"

enum class op_type
{
	any,
	reg,
	mem,
	imm,
	copy
};
struct operand
{
	// any reg mem imm copy
	op_type type;

	// x86
	union
	{
		xed_reg_enum_t reg;

		struct
		{
			xed_reg_enum_t seg;
			xed_reg_enum_t base;
			xed_reg_enum_t index;
			xed_uint_t scale;
			xed_enc_displacement_t disp;
			xed_uint_t width_bits;
		} mem;

		struct
		{
			xed_uint64_t v;
			xed_uint_t width_bits;
		} imm;

		// copy
		struct
		{
			// instruction index, operand index
			int i, j;
		} copy;
	};

	operand(op_type, int k, int j)
	{
	}
};
struct instruction
{
	xed_iclass_enum_t iclass;
	std::vector<operand> op;
	xed_encoder_operand_t operand_array[XED_ENCODER_OPERANDS_MAX];
};
struct pattern
{
	std::vector<instruction> match;
	std::vector<instruction> replace;
};

bool compare_op(struct operand& p_op, std::shared_ptr<x86_instruction> xed_instruction, int i)
{
	switch (p_op.type)
	{
		case op_type::any: return true;
		case op_type::reg:
		{
			auto xed_operand = xed_instruction->get_operand(i);
			return xed_operand.is_register() && p_op.reg == xed_instruction->get_register(xed_operand.get_name());
		}
		case op_type::mem:
		{
			auto xed_operand = xed_instruction->get_operand(i);
			if (!xed_operand.is_memory())
				return false;

			// how do i check second memory operand here?
			return p_op.mem.seg == xed_instruction->get_segment_register()
				&& p_op.mem.base == xed_instruction->get_base_register()
				&& p_op.mem.index == xed_instruction->get_index_register()
				&& p_op.mem.scale == xed_instruction->get_scale()
				&& p_op.mem.disp.displacement == xed_instruction->get_memory_displacement();
		}
		case op_type::imm:
		{
			auto xed_operand = xed_instruction->get_operand(i);
			if (!xed_operand.is_immediate())
				return false;

			// how do i check second immediate here?
			return p_op.imm.v == xed_instruction->get_unsigned_immediate();
		}
		default:
			break;
	}
}
bool compare_inst(struct instruction& inst, std::shared_ptr<x86_instruction> xed_instruction)
{
	if (xed_instruction->get_iclass() != inst.iclass)
		return false;

	for (int i = 0; i < inst.op.size(); i++)
	{
		if (!compare_op(inst.op[i], xed_instruction, i))
		{
			return false;
		}
	}
	return true;
}

xed_encoder_operand_t encode_operand(const operand& op, std::vector<std::shared_ptr<x86_instruction>>& source)
{
	switch (op.type)
	{
		case op_type::reg:
		{
			return xed_reg(op.reg);
		}
		case op_type::mem:
		{
			return xed_mem_gbisd(op.mem.seg, op.mem.base, op.mem.index, op.mem.scale, op.mem.disp, op.mem.width_bits);
		}
		case op_type::imm:
		{
			return xed_imm0(op.imm.v, op.imm.width_bits);
		}
		case op_type::copy:
		{
			operand copy_op(0,0);
			std::shared_ptr<x86_instruction> source_inst = source[op.copy.i];
			if (source[op.copy.i]->get_operand(op.copy.j).is_register())
			{
				copy_op.type = op_type::reg;
				copy_op.reg = source_inst->get_register(source[op.copy.i]->get_operand(op.copy.j).get_name());
			}
			else if (source[op.copy.i]->get_operand(op.copy.j).is_memory())
			{
				copy_op.type = op_type::mem;
				copy_op.mem.width_bits = source_inst->get_memory_operand_length() << 3;
				copy_op.mem.seg = source_inst->get_segment_register();
				copy_op.mem.base = source_inst->get_base_register();
				copy_op.mem.index = source_inst->get_index_register();
				copy_op.mem.scale = source_inst->get_scale();
				copy_op.mem.disp = xed_disp(source_inst->get_memory_displacement(), source_inst->get_memory_displacement_width());
			}
			else if (source[op.copy.i]->get_operand(op.copy.j).is_immediate())
			{
				copy_op.type = op_type::imm;
				copy_op.imm.v = source_inst->get_unsigned_immediate();
				copy_op.imm.width_bits = source_inst->get_immediate_width_bits();
			}
			return encode_operand(copy_op, source);
		}
		default:
			break;
	}
}

std::list<std::shared_ptr<x86_instruction>> repl(
	pattern p, std::vector<std::shared_ptr<x86_instruction>>& source,
	xed_machine_mode_enum_t mmode,
	xed_address_width_enum_t stack_addr_width)
{
	std::list<std::shared_ptr<x86_instruction>> result;
	for (int i = 0; i < p.replace.size(); i++)
	{
		xed_encoder_operand_t operand_array[XED_ENCODER_OPERANDS_MAX];
		xed_uint_t number_of_operands = p.replace[i].op.size();
		for (xed_uint_t operand_index = 0; operand_index < number_of_operands; operand_index++)
		{
			auto& op = p.replace[i].op[operand_index];
			operand_array[operand_index] = encode_operand(op, source);
		}

		xed_encoder_instruction_t x;
		xed_encoder_request_t enc_req;
		xed_state_t dstate;
		dstate.mmode = mmode;
		dstate.stack_addr_width = stack_addr_width;

		xed_inst(&x, dstate, p.replace[i].iclass, 0, number_of_operands, operand_array);

		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		auto convert_ok = xed_convert_to_encoder_request(&enc_req, &x);
		if (!convert_ok) {
			fprintf(stderr, "conversion to encode request failed\n");
			continue;
		}

		unsigned int olen;
		unsigned char itext[16];
		auto xed_error = xed_encode(&enc_req, itext, 16, &olen);

		std::shared_ptr<x86_instruction> xed_instruction = std::make_shared<x86_instruction>();
		xed_instruction->decode(itext, olen, mmode, stack_addr_width);
		result.push_back(std::move(xed_instruction));
	}
	return result;
}

void match(std::list<std::shared_ptr<x86_instruction>> xed_instructions)
{
	xed_machine_mode_enum_t mmode;
	xed_address_width_enum_t stack_addr_width;
	auto f = *xed_instructions.begin();
	mmode = f->get_machine_mode();
	stack_addr_width = f->get_stack_addr_width();


	pattern p;
	std::vector<std::shared_ptr<x86_instruction>> matched_inst;
	auto remove_it = xed_instructions.begin();
	for (auto it = xed_instructions.begin(); it != xed_instructions.end();)
	{
		const std::shared_ptr<x86_instruction>& xed_instruction = *it;
		if (compare_inst(p.match[matched_inst.size()], xed_instruction))
		{
			if (matched_inst.empty())
				remove_it = it;

			matched_inst.push_back(xed_instruction);
			if (matched_inst.size() == p.match.size())
			{
				// replace now
				auto r = repl(p, matched_inst, mmode, stack_addr_width);
				it = xed_instructions.erase(remove_it, std::next(it));
				it = xed_instructions.insert(it, r.begin(), r.end());

				matched_inst.clear();
				continue;
			}
		}
		else
		{
			matched_inst.clear();
		}

		++it;
	}
}

static void test()
{
	pattern p;
	p.match =
	{
		{
			XED_ICLASS_MOV, { { op_type::any } }
		},
		{
			XED_ICLASS_MOV, { { op_type::any } }
		}
	};
	p.replace =
	{
		{
			XED_ICLASS_MOV, { { op_type::copy, 0, 1 }, { op_type::copy, 0, 1 } }
		}
	};
}