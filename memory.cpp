#include "memory.hpp"

using namespace std;

MemorySpace::MemorySpace(const MemorySpace &ms) {
	m_initializer = ms.m_initializer;

	for (auto mse : m_space) {
		m_space[mse.first] = std::make_shared<MemoryValue>(*mse.second);
	}
}

bool MemorySpace::GetValue(MemoryAddress addr, MemoryValue &value) {
	if (m_space[addr]) {
		value = *m_space[addr];
		return true;
	}
	return false;
}

void MemorySpace::SetValue(const MemoryValue &value) {
	m_space[value.GetLocation()] = std::make_shared<MemoryValue>(value);
	return;
}
