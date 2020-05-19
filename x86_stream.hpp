#pragma once

class x86_instruction;

class x86_stream
{
protected:
	bool m_x86_64;
	uint64_t m_pos;

	x86_stream(bool x86_64);
	virtual ~x86_stream();

public:
	// impl
	virtual bool is_open() const = 0;
	virtual void close() = 0;

	virtual uint32_t read(void* buf, uint32_t size) = 0;
	virtual uint32_t write(const void* buf, uint32_t size) = 0;

	virtual uint64_t pos() const;
	virtual void seek(uint64_t pos);

	// x86_stream
	bool is_x86_64() const { return this->m_x86_64; }
	std::shared_ptr<x86_instruction> next();
};