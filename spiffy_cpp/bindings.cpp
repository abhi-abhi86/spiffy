#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
#include "network_scanner.h"
#include "crypto_accelerator.h"
#include "data_processor.h"

namespace py = pybind11;

PYBIND11_MODULE(spiffy_cpp, m) {
    m.doc() = "High-performance C++ modules for Spiffy security suite";

    // NetworkScanner class
    py::class_<spiffy::NetworkScanner>(m, "NetworkScanner")
        .def(py::init<int>(), py::arg("max_threads") = 100,
             "Create a network scanner with specified thread pool size")
        .def("scan_port", &spiffy::NetworkScanner::scan_port,
             py::arg("ip"), py::arg("port"), py::arg("timeout_ms") = 1500,
             "Scan a single port on a host")
        .def("scan_ports", &spiffy::NetworkScanner::scan_ports,
             py::arg("ip"), py::arg("ports"), py::arg("timeout_ms") = 1500,
             "Scan multiple ports on a host")
        .def("ping_host", &spiffy::NetworkScanner::ping_host,
             py::arg("ip"), py::arg("timeout_ms") = 1000,
             "Check if a host is alive")
        .def("ping_sweep", &spiffy::NetworkScanner::ping_sweep,
             py::arg("subnet"), py::arg("start_host") = 1, py::arg("end_host") = 254,
             "Perform ping sweep across a subnet")
        .def("grab_banner", &spiffy::NetworkScanner::grab_banner,
             py::arg("ip"), py::arg("port"), py::arg("timeout_ms") = 1500,
             "Grab service banner from a port");

    // CryptoAccelerator class
    py::class_<spiffy::CryptoAccelerator>(m, "CryptoAccelerator")
        .def(py::init<>(), "Create a crypto accelerator")
        .def("aes_gcm_encrypt", &spiffy::CryptoAccelerator::aes_gcm_encrypt,
             py::arg("plaintext"), py::arg("key"),
             "Encrypt data using AES-256-GCM")
        .def("aes_gcm_decrypt", &spiffy::CryptoAccelerator::aes_gcm_decrypt,
             py::arg("ciphertext"), py::arg("key"),
             "Decrypt data using AES-256-GCM")
        .def("generate_random", &spiffy::CryptoAccelerator::generate_random,
             py::arg("num_bytes"),
             "Generate secure random bytes")
        .def("sha256", &spiffy::CryptoAccelerator::sha256,
             py::arg("data"),
             "Compute SHA-256 hash")
        .def("pbkdf2", &spiffy::CryptoAccelerator::pbkdf2,
             py::arg("password"), py::arg("salt"), 
             py::arg("iterations"), py::arg("key_length"),
             "Derive key using PBKDF2");

    // DataProcessor class
    py::class_<spiffy::DataProcessor>(m, "DataProcessor")
        .def(py::init<>(), "Create a data processor")
        .def("resolve_mac_vendor", &spiffy::DataProcessor::resolve_mac_vendor,
             py::arg("mac"), py::arg("oui_db"),
             "Resolve MAC address to vendor name")
        .def("normalize_mac", &spiffy::DataProcessor::normalize_mac,
             py::arg("mac"),
             "Normalize MAC address format")
        .def("generate_ip_range", &spiffy::DataProcessor::generate_ip_range,
             py::arg("subnet"), py::arg("start"), py::arg("end"),
             "Generate IP address range")
        .def("extract_subnet", &spiffy::DataProcessor::extract_subnet,
             py::arg("ip"),
             "Extract subnet from IP address")
        .def("fast_search", &spiffy::DataProcessor::fast_search,
             py::arg("text"), py::arg("pattern"),
             "Fast string search using Boyer-Moore algorithm");

    // Version info
    m.attr("__version__") = "1.0.0";
    m.attr("__author__") = "Spiffy Security Suite";
}
