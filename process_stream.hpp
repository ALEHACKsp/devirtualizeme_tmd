#pragma once

#include "x86_stream.hpp"

class process_stream final : public x86_stream
{
public:
	process_stream(bool x86_64 = false);
	~process_stream();

	// override
	bool is_open() const override;
	void close() override;

	uint32_t read(void* buf, uint32_t size) override;
	uint32_t write(const void* buf, uint32_t size) override;

	// process specific
	bool open(unsigned long pid);

	// case sensitive for now
	bool open(const std::string& process_name);

	// return 0 if not open
	unsigned long pid() const;

private:
	unsigned long m_pid;
	void* m_handle;
};