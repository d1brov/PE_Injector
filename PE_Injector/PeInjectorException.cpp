#include "PeInjectorException.h"

#include <format>

PeInjectorException::PeInjectorException(const std::string& message)
	: message_(message) {
}

const char* PeInjectorException::what() const noexcept {
	return message_.c_str();
}
