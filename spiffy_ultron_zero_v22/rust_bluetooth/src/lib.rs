// Rust Backend - Security Scoring Engine
// Does heavy cryptographic analysis
// Python just calls this

use pyo3::prelude::*;
use std::collections::HashMap;

#[pyclass]
struct SecurityAnalyzer {
    // Internal state
}

#[pymethods]
impl SecurityAnalyzer {
    #[new]
    fn new() -> Self {
        SecurityAnalyzer {}
    }
    
    /// Complete security analysis - returns full report
    fn analyze_device(&self, bluetooth_version: &str, encryption: &str, 
                     key_size: u16, has_vulnerabilities: bool) -> PyResult<HashMap<String, String>> {
        let mut analysis = HashMap::new();
        
        // Pairing method determination
        let pairing = self.determine_pairing_method(bluetooth_version);
        analysis.insert("pairing_method".to_string(), pairing.clone());
        
        // Encryption strength
        let enc_strength = self.analyze_encryption(encryption, key_size);
        analysis.insert("encryption_strength".to_string(), enc_strength);
        
        // Risk level calculation
        let risk = self.calculate_risk(&pairing, encryption, has_vulnerabilities);
        analysis.insert("risk_level".to_string(), risk);
        
        // Security score (0-100)
        let score = self.calculate_security_score(&pairing, encryption, key_size, has_vulnerabilities);
        analysis.insert("security_score".to_string(), score.to_string());
        
        Ok(analysis)
    }
    
    fn determine_pairing_method(&self, version: &str) -> String {
        match version {
            v if v >= "4.2" => "SSP_NUMERIC_COMPARISON".to_string(),
            v if v >= "2.1" => "SSP".to_string(),
            _ => "LEGACY_PIN".to_string()
        }
    }
    
    fn analyze_encryption(&self, encryption: &str, key_size: u16) -> String {
        match (encryption, key_size) {
            ("AES-CCM", 256) | ("AES-GCM", 256) => "EXCELLENT".to_string(),
            ("AES-CCM", 128) | ("AES-GCM", 128) => "GOOD".to_string(),
            ("E0", _) => "WEAK".to_string(),
            _ => "UNKNOWN".to_string()
        }
    }
    
    fn calculate_risk(&self, pairing: &str, encryption: &str, has_vulns: bool) -> String {
        if has_vulns || encryption.contains("WEAK") {
            "HIGH".to_string()
        } else if pairing == "LEGACY_PIN" {
            "MEDIUM".to_string()
        } else if encryption.contains("E0") {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        }
    }
    
    fn calculate_security_score(&self, pairing: &str, encryption: &str, 
                                key_size: u16, has_vulns: bool) -> u8 {
        let mut score: u8 = 100;
        
        // Pairing penalty
        score -= match pairing {
            "LEGACY_PIN" => 30,
            "SSP" => 10,
            _ => 0
        };
        
        // Encryption penalty
        score -= match encryption {
            e if e.contains("WEAK") => 40,
            "E0" => 20,
            _ => 0
        };
        
        // Key size penalty
        if key_size < 128 {
            score -= 20;
        }
        
        // Vulnerability penalty
        if has_vulns {
            score -= 30;
        }
        
        score
    }
    
    /// Batch analysis for multiple devices
    fn analyze_batch(&self, devices: Vec<HashMap<String, String>>) -> PyResult<Vec<HashMap<String, String>>> {
        let mut results = Vec::new();
        
        for device in devices {
            let version = device.get("bluetooth_version").map(|s| s.as_str()).unwrap_or("Unknown");
            let encryption = device.get("encryption").map(|s| s.as_str()).unwrap_or("Unknown");
            let key_size = device.get("key_size").and_then(|s| s.parse().ok()).unwrap_or(0);
            let has_vulns = device.get("has_vulnerabilities").map(|s| s == "true").unwrap_or(false);
            
            let analysis = self.analyze_device(version, encryption, key_size, has_vulns)?;
            results.push(analysis);
        }
        
        Ok(results)
    }
}

#[pymodule]
fn rust_bluetooth(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SecurityAnalyzer>()?;
    Ok(())
}
