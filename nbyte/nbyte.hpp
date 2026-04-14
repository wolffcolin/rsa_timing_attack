#pragma once

#include <cstddef>
#include <cstring>
#include <iostream>
#include <initializer_list>

template<size_t N> class nbyte;
template<size_t N> std::ostream& operator<<(std::ostream& os, const nbyte<N>& obj);

template<size_t N>
class nbyte
{
private:
	u_int8_t m_Data[N];
public:
	nbyte() {
		std::memset(m_Data, 0, sizeof(m_Data));
	}
	nbyte(u_int8_t n) {
		m_Data[N-1] = n;
	}
	nbyte(std::initializer_list<bool> list) {
		for (size_t i = 0; i < N; i++) {
			for (size_t j = 0; j < 8; j++) {;
				if (i*8+j >= list.size())
					return;
				m_Data[i] = (m_Data[i] << 1) + list.begin()[i*8+j];
				// std::cout << list.begin()[i*8+j] << std::endl;
			}
		}
	}
	nbyte(nbyte<N>& other) {
		for (size_t i = 0; i < N; i++) {
			m_Data[i] = other.m_Data[i];
		}
	}
	~nbyte() = default;

	nbyte<N> operator^(nbyte<N>& other) {
		nbyte<N> result;
		for (size_t i = 0; i < N; i++) {
			result.m_Data[i] = m_Data[i] ^ other.m_Data[i];
		}
		return result;
	}

	nbyte<N>& operator+=(nbyte<N>& other) {
		u_int16_t carry = 0;
		for (int i = N-1; i >= 0; --i) {
			carry += m_Data[i] + (u_int16_t) other.m_Data[i];
			m_Data[i] = (u_int8_t) carry;
			carry = carry >> 8;
		}
		return *this;
	}

	nbyte<N> operator+(nbyte<N>& other) {
		nbyte<N> result(*this);
		result += other;
		return result;
	}

	nbyte<N> shiftLeft1() {
		nbyte<N> result;
		for (int i = 0; i < N-1; i++) {
			result.m_Data[i] = (m_Data[i] << 1) + (m_Data[i+1] >> 7);
		}
		result.m_Data[N-1] = (m_Data[N-1] << 1);
		return result;
	}

	nbyte<N> operator*(nbyte<N>& other) {
		nbyte<N> result;
		for (int i = 0; i < N-1; i++) {
			for (int j = 0; j < 8; j++) {
				if (((m_Data[i] >> j) & 1) == 1) {
					result += other;
				}
				result = result.shiftLeft1();
			}
		}
		for (int j = 0; j < 7; j++) {
			if (((m_Data[N-1] >> j) & 1) == 1) {
				result += other;
			}
			result = result.shiftLeft1();
		}
		if ((m_Data[N-1] >> 7) == 1) {
			result += other;
		}
		return result;
	}

	friend std::ostream& operator<< <>(std::ostream& os, const nbyte<N>& obj);
};

template<size_t N>
std::ostream& operator<<(std::ostream& os, const nbyte<N>& obj) {
	for (size_t i = 0; i < N; i++) {
		for (int j = 7; j >= 0; --j) {
			os << ((obj.m_Data[i] >> j) & 1);
		}
	}
	return os;
}