#pragma once

#include <exception>
#include <string>

class PeInjectorException : public std::exception {
public:
	PeInjectorException() = default;
	explicit PeInjectorException(const std::string& message);
	const char* what() const noexcept override;

private:
	std::string message_;
};