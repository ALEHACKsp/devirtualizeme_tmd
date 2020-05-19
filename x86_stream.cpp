#include "pch.h"

#include "x86_stream.hpp"
#include "x86_instruction.hpp"

x86_stream::x86_stream(bool x86_64)
{
	this->m_x86_64 = x86_64;
	this->m_pos = 0;
}
x86_stream::~x86_stream()
{
}

uint64_t x86_stream::pos() const
{
	return this->m_pos;
}
void x86_stream::seek(uint64_t pos)
{
	if (!this->is_open())
		throw std::runtime_error("process is not open");

	this->m_pos = pos;
}

std::shared_ptr<x86_instruction> x86_stream::next()
{
	constexpr uint32_t size = 16;
	xed_uint8_t buf[size];
	const uint64_t pos = this->pos();
	const uint32_t read_bytes = this->read(buf, size);

	std::shared_ptr<x86_instruction> inst = std::make_shared<x86_instruction>(pos);
	inst->decode(buf, read_bytes,
		this->m_x86_64 ? XED_MACHINE_MODE_LONG_64 : XED_MACHINE_MODE_LONG_COMPAT_32,
		this->m_x86_64 ? XED_ADDRESS_WIDTH_64b : XED_ADDRESS_WIDTH_32b);

	this->seek(pos + inst->get_length());
	return inst;
}