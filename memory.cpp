#include "memory.hpp"

using namespace std;

MemorySpace::MemorySpace(const MemorySpace &ms) {
	m_initializer = ms.m_initializer;

	for (auto mse : ms.m_memory) {
		m_memory[mse.first] = std::make_shared<MemoryValue>(*mse.second);
	}
	for (auto rse : ms.m_registers) {
		m_registers[rse.first] = std::make_shared<RegisterValue>(*rse.second);
	}
}

bool MemorySpace::GetMemoryValue(MemoryAddress_t addr, MemoryValue &value) {
	if (m_memory.end() != m_memory.find(addr)) {
		value = *m_memory[addr];
		return true;
	}
	return false;
}

void MemorySpace::SetMemoryValue(const MemoryValue &value) {
	m_memory[value.GetLocation()] = std::make_shared<MemoryValue>(value);
	return;
}

bool MemorySpace::GetRegisterValue(RegisterAddress_t addr, RegisterValue &value) {
	if (m_registers.end() != m_registers.find(addr)) {
		value = *m_registers[addr];
		return true;
	}
	return false;
}

void MemorySpace::SetRegisterValue(const RegisterValue &value) {
	m_registers[value.GetLocation()] = std::make_shared<RegisterValue>(value);
	return;
}
