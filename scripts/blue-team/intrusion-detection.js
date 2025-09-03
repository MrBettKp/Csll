#!/usr/bin/env node
/*
 * Advanced Intrusion Detection System
 * Monitors system activities and detects suspicious behaviors
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const https = require('https');
const crypto = require('crypto');

class IntrusionDetectionSystem {
    constructor(config = {}) {
        this.config = {
            logFile: '/var/log/ids.log',
            checkInterval: 30000, // 30 seconds
            criticalFiles: [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/sudoers',
                '/etc/ssh/sshd_config',
                '/root/.bash_history',
                '/root/.ssh/authorized_keys'
            ],
            monitorProcesses: [
                'sshd', 'apache2', 'nginx', 'mysql', 'postgresql'
            ],
            ...config
        };
        
        this.baselineHashes = new Map();
        this.establishedConnections = new Set();
    }
    
    // Initialize the IDS
    initialize() {
        console.log('Initializing Intrusion Detection System...');
        
        // Create log directory if it doesn't exist
        const logDir = path.dirname(this.config.logFile);
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
        
        // Establish baseline file hashes
        this.createBaselineHashes();
        
        // Start monitoring
        this.startMonitoring();
    }
    
    // Create baseline hashes for critical files
    createBaselineHashes() {
        console.log('Creating baseline hashes for critical files...');
        
        for (const file of this.config.criticalFiles) {
            if (fs.existsSync(file)) {
                try {
                    const hash = this.calculateFileHash(file);
                    this.baselineHashes.set(file, hash);
                    this.logEvent('BASELINE', `Baseline hash created for ${file}: ${hash}`);
                } catch (error) {
                    this.logEvent('ERROR', `Failed to create baseline for ${file}: ${error.message}`);
                }
            }
        }
    }
    
    // Calculate MD5 hash of a file
    calculateFileHash(filePath) {
        const fileBuffer = fs.readFileSync(filePath);
        const hashSum = crypto.createHash('md5');
        hashSum.update(fileBuffer);
        return hashSum.digest('hex');
    }
    
    // Monitor for changes
    startMonitoring() {
        console.log('Starting continuous monitoring...');
        
        // Check file integrity periodically
        setInterval(() => {
            this.checkFileIntegrity();
            this.checkNetworkConnections();
            this.checkProcesses();
        }, this.config.checkInterval);
        
        // Real-time monitoring with inotifywait if available
        this.setupRealTimeMonitoring();
    }
    
    // Check for changes in critical files
    checkFileIntegrity() {
        for (const [file, baselineHash] of this.baselineHashes) {
            if (fs.existsSync(file)) {
                try {
                    const currentHash = this.calculateFileHash(file);
                    if (currentHash !== baselineHash) {
                        this.logEvent('ALERT', `File modified: ${file}`);
                        this.baselineHashes.set(file, currentHash); // Update baseline
                    }
                } catch (error) {
                    this.logEvent('ERROR', `Failed to check integrity of ${file}: ${error.message}`);
                }
            } else {
                this.logEvent('ALERT', `Critical file missing: ${file}`);
            }
        }
    }
    
    // Check network connections for suspicious activities
    checkNetworkConnections() {
        try {
            const netstat = execSync('netstat -tupan 2>/dev/null | grep ESTABLISHED', { encoding: 'utf8' });
            const connections = netstat.trim().split('\n').filter(line => line);
            
            for (const line of connections) {
                const parts = line.split(/\s+/);
                if (parts.length >= 7) {
                    const proto = parts[0];
                    const local = parts[3];
                    const foreign = parts[4];
                    const pid = parts[6];
                    
                    const connId = `${proto}-${local}-${foreign}`;
                    
                    if (!this.establishedConnections.has(connId)) {
                        this.establishedConnections.add(connId);
                        this.logEvent('INFO', `New connection: ${proto} ${local} -> ${foreign} (PID: ${pid})`);
                    }
                }
            }
        } catch (error) {
            this.logEvent('ERROR', `Failed to check network connections: ${error.message}`);
        }
    }
    
    // Monitor critical processes
    checkProcesses() {
        for (const process of this.config.monitorProcesses) {
            try {
                const result = execSync(`pgrep -x ${process}`, { encoding: 'utf8' });
                if (!result.trim()) {
                    this.logEvent('ALERT', `Critical process not running: ${process}`);
                }
            } catch (error) {
                this.logEvent('ALERT', `Critical process not running: ${process}`);
            }
        }
    }
    
    // Setup real-time file monitoring with inotifywait
    setupRealTimeMonitoring() {
        // Check if inotifywait is available
        try {
            execSync('which inotifywait', { stdio: 'ignore' });
            
            // Monitor critical files for changes
            const inotify = spawn('inotifywait', [
                '-m', '-r', '-e', 'modify,attrib,move,create,delete',
                ...this.config.criticalFiles.filter(file => fs.existsSync(file))
            ]);
            
            inotify.stdout.on('data', (data) => {
                const message = data.toString().trim();
                this.logEvent('ALERT', `Real-time file change detected: ${message}`);
            });
            
            inotify.stderr.on('data', (data) => {
                this.logEvent('ERROR', `inotifywait error: ${data.toString().trim()}`);
            });
            
        } catch (error) {
            this.logEvent('WARNING', 'inotifywait not available, real-time monitoring disabled');
        }
    }
    
    // Log events to file and console
    logEvent(level, message) {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] [${level}] ${message}`;
        
        // Write to log file
        fs.appendFileSync(this.config.logFile, logMessage + '\n');
        
        // Also output to console for important events
        if (level === 'ALERT' || level === 'ERROR') {
            console.log(logMessage);
            
            // Optional: Send alerts via HTTP/webhook
            if (this.config.webhookUrl) {
                this.sendWebhookAlert(level, message);
            }
        }
    }
    
    // Send alert via webhook
    sendWebhookAlert(level, message) {
        const data = JSON.stringify({
            text: `[${level}] ${message}`
        });
        
        const options = {
            hostname: new URL(this.config.webhookUrl).hostname,
            port: 443,
            path: new URL(this.config.webhookUrl).pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': data.length
            }
        };
        
        const req = https.request(options, (res) => {
            // Request successful
        });
        
        req.on('error', (error) => {
            this.logEvent('ERROR', `Webhook alert failed: ${error.message}`);
        });
        
        req.write(data);
        req.end();
    }
}

// Main execution
if (require.main === module) {
    const ids = new IntrusionDetectionSystem();
    ids.initialize();
    
    // Keep the process running
    process.stdin.resume();
    console.log('Intrusion Detection System is running. Press Ctrl+C to stop.');
    
    process.on('SIGINT', () => {
        console.log('\nShutting down Intrusion Detection System...');
        process.exit(0);
    });
}

module.exports = IntrusionDetectionSystem;
