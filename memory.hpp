#ifndef _MEMORY_HPP
#define _MEMORY_HPP

#include <stdint.h>
#include <iostream>
#include <map>
#include <memory>

typedef uint64_t ValueContents_t;
typedef uint64_t ValueAddress_t;
typedef uint64_t MemoryAddress_t;
typedef uint64_t RegisterAddress_t;

class Value
{
	public:
		Value() :
			m_value(0),
			m_tainted(false),
			m_location(0) {}
		Value(ValueAddress_t location) :
			m_value(0),
			m_tainted(false),
			m_location(location) {}
		Value(const Value &v) : 
			m_value(v.GetValue()),
			m_tainted(v.GetTainted()),
			m_location(v.GetLocation()) {}

		virtual ValueContents_t GetValue() const {
			return m_value;
		}

		virtual ValueAddress_t GetLocation() const {
			return m_location;
		}

		virtual bool GetTainted() const {
			return m_tainted;
		}

		virtual void SetValue(ValueContents_t value) {
			m_value = value;
		}
		
		virtual void SetTainted(bool tainted) {
			m_tainted = tainted;
		}

		virtual void SetLocation(const ValueAddress_t location) {
			m_location = location;
		}

		~Value() { }

	private:
		ValueContents_t m_value;
		bool m_tainted;
		ValueAddress_t m_location;


};

class RegisterValue : public Value
{
  using Value::Value;
  public:
    static constexpr ValueContents_t DefaultRegisterValue() { 
	return 0x11111100UL;
    }
};

class MemoryValue : public Value
{
  using Value::Value;
};

class MemorySpace
{
	public:
		MemorySpace(uint32_t initializer) : m_initializer(initializer) {};
		MemorySpace(const MemorySpace &ms);

		uint32_t GetInitializer() {
		    return m_initializer++;
		}
		bool GetMemoryValue(MemoryAddress_t addr, MemoryValue &value);
		void SetMemoryValue(const MemoryValue &value);

		bool GetRegisterValue(RegisterAddress_t addr, RegisterValue
				      &value);
		void SetRegisterValue(const RegisterValue &value);

		~MemorySpace() { }
	private:
		uint64_t m_initializer;
		std::map<MemoryAddress_t, std::shared_ptr<MemoryValue>> 
		  m_memory;
		std::map<RegisterAddress_t, std::shared_ptr<RegisterValue>> 
		  m_registers;
};

#endif
