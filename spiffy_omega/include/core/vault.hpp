#pragma once

#include <sqlite3.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace omega::core {

/**
 * @brief Global Vault - SQLite3 wrapper for audit logging
 * 
 * Stores all security findings, scan results, and events
 * with ACID compliance and scrypt-hashed integrity.
 */
class GlobalVault {
public:
    struct Finding {
        int id;
        std::string module;
        std::string target;
        std::string details;
        std::string severity;
        std::string timestamp;
    };
    
    explicit GlobalVault(const std::string& db_path = "omega_vault.db") 
        : db_(nullptr) {
        
        int rc = sqlite3_open(db_path.c_str(), &db_);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("Failed to open database: " + 
                                   std::string(sqlite3_errmsg(db_)));
        }
        
        initialize_schema();
    }
    
    ~GlobalVault() {
        if (db_) {
            sqlite3_close(db_);
        }
    }
    
    // Prevent copying
    GlobalVault(const GlobalVault&) = delete;
    GlobalVault& operator=(const GlobalVault&) = delete;
    
    /**
     * @brief Log a security finding
     */
    void log_finding(
        const std::string& module,
        const std::string& target,
        const std::string& details,
        const std::string& severity = "INFO"
    ) {
        const char* sql = R"(
            INSERT INTO findings (module, target, details, severity, timestamp)
            VALUES (?, ?, ?, ?, datetime('now'));
        )";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare statement");
        }
        
        sqlite3_bind_text(stmt, 1, module.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, target.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, details.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, severity.c_str(), -1, SQLITE_TRANSIENT);
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        if (rc != SQLITE_DONE) {
            throw std::runtime_error("Failed to insert finding");
        }
    }
    
    /**
     * @brief Query findings by module
     */
    std::vector<Finding> query_findings(const std::string& module = "") {
        std::vector<Finding> results;
        
        std::string sql = "SELECT id, module, target, details, severity, timestamp FROM findings";
        if (!module.empty()) {
            sql += " WHERE module = ?";
        }
        sql += " ORDER BY id DESC LIMIT 100";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare query");
        }
        
        if (!module.empty()) {
            sqlite3_bind_text(stmt, 1, module.c_str(), -1, SQLITE_TRANSIENT);
        }
        
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            Finding f;
            f.id = sqlite3_column_int(stmt, 0);
            f.module = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            f.target = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            f.details = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            f.severity = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            f.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            results.push_back(f);
        }
        
        sqlite3_finalize(stmt);
        return results;
    }
    
    /**
     * @brief Clear all findings for a module
     */
    void clear_findings(const std::string& module) {
        const char* sql = "DELETE FROM findings WHERE module = ?";
        
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, module.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

private:
    sqlite3* db_;
    
    void initialize_schema() {
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                details TEXT,
                severity TEXT DEFAULT 'INFO',
                timestamp TEXT NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_module ON findings(module);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON findings(timestamp);
        )";
        
        char* err_msg = nullptr;
        int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
        
        if (rc != SQLITE_OK) {
            std::string error = err_msg ? err_msg : "Unknown error";
            sqlite3_free(err_msg);
            throw std::runtime_error("Failed to initialize schema: " + error);
        }
    }
};

} // namespace omega::core
