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

bool MemorySpace::GetMemoryValue(MemoryValue &value) {
    if (m_memory.end() != m_memory.find(value.GetLocation())) {
	value = *m_memory[value.GetLocation()];
	cout << "Get: "<<  std::hex << value.GetLocation() << ": "<<std::hex<<
	  value.GetValue() << "." << endl;
	return true;
    }
    return false;
}

void MemorySpace::SetMemoryValue(const MemoryValue &value) {
    cout << "Set: "<<  std::hex << value.GetLocation() << ": " << std::hex <<
      value.GetValue() << "." << endl;
    m_memory[value.GetLocation()] = std::make_shared<MemoryValue>(value);
    return;
}

bool MemorySpace::GetRegisterValue(RegisterValue &value) {
    if (m_registers.end() != m_registers.find(value.GetLocation())) {
	value = *m_registers[value.GetLocation()];
	return true;
    }
    return false;
}

void MemorySpace::SetRegisterValue(const RegisterValue &value) {
    m_registers[value.GetLocation()]=std::make_shared<RegisterValue>(value);
    return;
}

ostream& operator<<(ostream &os, const Value &mv) {
    os << "Value: " << std::hex
      << mv.GetValue()
      << " at " << std::hex
      << mv.GetLocation();
    if (mv.GetTainted()) {
	os << " (tainted)";
    }
    os << ".";
    return os;
}
