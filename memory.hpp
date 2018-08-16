#ifndef _MEMORY_HPP
#define _MEMORY_HPP

#include <stdint.h>
#include <iostream>
#include <map>
#include <memory>

typedef uint64_t MemoryAddress;

class MemoryValue
{
	public:
		MemoryValue() :
			m_value(0),
			m_tainted(false),
			m_location(0) {}
		MemoryValue(MemoryAddress location) :
			m_value(0),
			m_tainted(false),
			m_location(location) {}
		MemoryValue(const MemoryValue &v) : 
			m_value(v.GetValue()),
			m_tainted(v.GetTainted()),
			m_location(v.GetLocation()) {}

		virtual uint32_t GetValue() const {
			return m_value;
		}

		virtual MemoryAddress GetLocation() const {
			return m_location;
		}

		virtual bool GetTainted() const {
			return m_tainted;
		}

		virtual void SetValue(uint32_t value) {
			m_value = value;
		}
		
		virtual void SetTainted(bool tainted) {
			m_tainted = tainted;
		}

		virtual void SetLocation(const MemoryAddress location) {
			m_location = location;
		}

		~MemoryValue() { }

	private:
		uint32_t m_value;
		bool m_tainted;
		MemoryAddress m_location;


};

class RegisterMemoryValue : MemoryValue
{
};

class MemoryMemoryValue : MemoryValue
{
};

class MemorySpace
{
	public:
		MemorySpace(uint64_t initializer) : m_initializer(initializer) {};
		MemorySpace(const MemorySpace &ms);

		bool GetValue(MemoryAddress addr, MemoryValue &value);
		void SetValue(const MemoryValue &value);

		~MemorySpace() { }
	private:
		uint64_t m_initializer;
		std::map<MemoryAddress, std::shared_ptr<MemoryValue>> m_space;
};

#endif
