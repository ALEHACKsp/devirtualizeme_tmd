#include "pch.h"

#include "triton.hpp"

triton::uint64 getStackPointerValue(triton::API* api)
{
	return api->getConcreteRegisterValue(api->getCpuInstance()->getStackPointer()).convert_to<triton::uint64>();
}
triton::uint64 getProgramCounterValue(triton::API* api)
{
	return api->getConcreteRegisterValue(api->getCpuInstance()->getProgramCounter()).convert_to<triton::uint64>();
}