#!/usr/bin/env node
/*
 * Advanced Password Cracker
 * Supports dictionary, brute force, and hybrid attacks
 * Works with various hash types
 */

const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');
const { execSync } = require('child_process');

class PasswordCracker {
    constructor(options = {}) {
        this.options = {
            maxLength: 8,
            characterSet: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            dictionaryFile: '/usr/share/wordlists/rockyou.txt',
            ...options
        };
        
        this.hashTypes = {
            'md5': this.hashMD5,
            'sha1': this.hashSHA1,
            'sha256': this.hashSHA256,
            'sha512': this.hashSHA512,
            'ntlm': this.hashNTLM
        };
    }
    
    // Hash functions
    hashMD5(password) {
        return crypto.createHash('md5').update(password).digest('hex');
    }
    
    hashSHA1(password) {
        return crypto.createHash('sha1').update(password).digest('hex');
    }
    
    hashSHA256(password) {
        return crypto.createHash('sha256').update(password).digest('hex');
    }
    
    hashSHA512(password) {
        return crypto.createHash('sha512').update(password).digest('hex');
    }
    
    hashNTLM(password) {
        const md4 = require('js-md4');
        return md4(Buffer.from(password, 'utf16le')).toString('hex');
    }
    
    // Dictionary attack
    async dictionaryAttack(hash, hashType = 'md5') {
        console.log(`Starting dictionary attack (${hashType})...`);
        
        if (!fs.existsSync(this.options.dictionaryFile)) {
            console.error('Dictionary file not found:', this.options.dictionaryFile);
            return null;
        }
        
        const hashFunc = this.hashTypes[hashType];
        if (!hashFunc) {
            console.error('Unsupported hash type:', hashType);
            return null;
        }
        
        const fileStream = fs.createReadStream(this.options.dictionaryFile);
        const rl = readline.createInterface({
            input: fileStream,
            crlfDelay: Infinity
        });
        
        let attempts = 0;
        const startTime = Date.now();
        
        for await (const password of rl) {
            attempts++;
            
            if (attempts % 10000 === 0) {
                process.stdout.write(`\rAttempts: ${attempts.toLocaleString()} | Current: ${password}`);
            }
            
            const hashed = hashFunc(password);
            if (hashed === hash) {
                const endTime = Date.now();
                console.log(`\nPassword found: ${password}`);
                console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
                console.log(`Attempts: ${attempts.toLocaleString()}`);
                return password;
            }
        }
        
        const endTime = Date.now();
        console.log(`\nPassword not found in dictionary`);
        console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
        console.log(`Attempts: ${attempts.toLocaleString()}`);
        return null;
    }
    
    // Brute force attack
    async bruteForceAttack(hash, hashType = 'md5', maxLength = null) {
        console.log(`Starting brute force attack (${hashType})...`);
        
        const length = maxLength || this.options.maxLength;
        const hashFunc = this.hashTypes[hashType];
        if (!hashFunc) {
            console.error('Unsupported hash type:', hashType);
            return null;
        }
        
        let attempts = 0;
        const startTime = Date.now();
        
        // Recursive function to generate all combinations
        const generate = async (current, depth) => {
            if (depth === 0) {
                attempts++;
                
                if (attempts % 100000 === 0) {
                    process.stdout.write(`\rAttempts: ${attempts.toLocaleString()} | Current: ${current}`);
                }
                
                const hashed = hashFunc(current);
                if (hashed === hash) {
                    const endTime = Date.now();
                    console.log(`\nPassword found: ${current}`);
                    console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
                    console.log(`Attempts: ${attempts.toLocaleString()}`);
                    return current;
                }
                return null;
            }
            
            for (const char of this.options.characterSet) {
                const result = await generate(current + char, depth - 1);
                if (result) return result;
            }
            
            return null;
        };
        
        for (let i = 1; i <= length; i++) {
            console.log(`Trying length ${i}...`);
            const result = await generate('', i);
            if (result) return result;
        }
        
        const endTime = Date.now();
        console.log(`\nPassword not found with brute force`);
        console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
        console.log(`Attempts: ${attempts.toLocaleString()}`);
        return null;
    }
    
    // Hybrid attack (dictionary + brute force)
    async hybridAttack(hash, hashType = 'md5') {
        console.log(`Starting hybrid attack (${hashType})...`);
        
        if (!fs.existsSync(this.options.dictionaryFile)) {
            console.error('Dictionary file not found:', this.options.dictionaryFile);
            return null;
        }
        
        const hashFunc = this.hashTypes[hashType];
        if (!hashFunc) {
            console.error('Unsupported hash type:', hashType);
            return null;
        }
        
        const fileStream = fs.createReadStream(this.options.dictionaryFile);
        const rl = readline.createInterface({
            input: fileStream,
            crlfDelay: Infinity
        });
        
        let attempts = 0;
        const startTime = Date.now();
        
        // Common suffixes and prefixes
        const commonMods = [
            '123', '1234', '12345', '123456', 
            '!', '@', '#', '$', '%', '&', '*',
            '?', '.', '0', '1', '00', '01', '99',
            '2020', '2021', '2022', '2023', '2024', '2025'
        ];
        
        for await (const basePassword of rl) {
            // Try the base password
            attempts++;
            let hashed = hashFunc(basePassword);
            if (hashed === hash) {
                const endTime = Date.now();
                console.log(`\nPassword found: ${basePassword}`);
                console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
                console.log(`Attempts: ${attempts.toLocaleString()}`);
                return basePassword;
            }
            
            // Try with common modifications
            for (const mod of commonMods) {
                // Suffix
                attempts++;
                const suffixed = basePassword + mod;
                hashed = hashFunc(suffixed);
                if (hashed === hash) {
                    const endTime = Date.now();
                    console.log(`\nPassword found: ${suffixed}`);
                    console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
                    console.log(`Attempts: ${attempts.toLocaleString()}`);
                    return suffixed;
                }
                
                // Prefix
                attempts++;
                const prefixed = mod + basePassword;
                hashed = hashFunc(prefixed);
                if (hashed === hash) {
                    const endTime = Date.now();
                    console.log(`\nPassword found: ${prefixed}`);
                    console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
                    console.log(`Attempts: ${attempts.toLocaleString()}`);
                    return prefixed;
                }
                
                // Both
                attempts++;
                const both = mod + basePassword + mod;
                hashed = hashFunc(both);
                if (hashed === hash) {
                    const endTime = Date.now();
                    console.log(`\nPassword found: ${both}`);
                    console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
                    console.log(`Attempts: ${attempts.toLocaleString()}`);
                    return both;
                }
            }
            
            if (attempts % 10000 === 0) {
                process.stdout.write(`\rAttempts: ${attempts.toLocaleString()} | Current: ${basePassword}`);
            }
        }
        
        const endTime = Date.now();
        console.log(`\nPassword not found with hybrid attack`);
        console.log(`Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds`);
        console.log(`Attempts: ${attempts.toLocaleString()}`);
        return null;
    }
    
    // Identify hash type
    identifyHash(hash) {
        const length = hash.length;
        
        if (length === 32) return 'md5';
        if (length === 40) return 'sha1';
        if (length === 64) return 'sha256';
        if (length === 128) return 'sha512';
        if (length === 32 && /^[0-9a-fA-F]{32}$/.test(hash)) return 'md5'; // NTLM is also 32 chars but different format
        
        return 'unknown';
    }
    
    // Benchmark hashing speed
    benchmark() {
        console.log('Benchmarking hash functions...');
        const testPassword = 'password123';
        const iterations = 100000;
        
        for (const [type, hashFunc] of Object.entries(this.hashTypes)) {
            const start = Date.now();
            for (let i = 0; i < iterations; i++) {
                hashFunc(testPassword + i);
            }
            const end = Date.now();
            const speed = iterations / ((end - start) / 1000);
            console.log(`${type}: ${Math.round(speed).toLocaleString()} hashes/sec`);
        }
    }
}

// Command line interface
async function main() {
    const args = process.argv.slice(2);
    if (args.length < 2) {
        console.log('Usage: password-cracker.js <attack-type> <hash> [options]');
        console.log('Attack types: dictionary, brute, hybrid, benchmark');
        console.log('Options:');
        console.log('  --hash-type <type>    md5, sha1, sha256, sha512, ntlm');
        console.log('  --max-length <n>      Maximum password length for brute force');
        console.log('  --dict <file>         Dictionary file path');
        process.exit(1);
    }
    
    const attackType = args[0];
    const hash = args[1];
    let options = {};
    
    // Parse options
    for (let i = 2; i < args.length; i++) {
        if (args[i] === '--hash-type' && args[i + 1]) {
            options.hashType = args[i + 1];
            i++;
        } else if (args[i] === '--max-length' && args[i + 1]) {
            options.maxLength = parseInt(args[i + 1]);
            i++;
        } else if (args[i] === '--dict' && args[i + 1]) {
            options.dictionaryFile = args[i + 1];
            i++;
        }
    }
    
    const cracker = new PasswordCracker(options);
    
    if (attackType === 'benchmark') {
        cracker.benchmark();
        process.exit(0);
    }
    
    // Auto-detect hash type if not specified
    if (!options.hashType) {
        options.hashType = cracker.identifyHash(hash);
        console.log(`Detected hash type: ${options.hashType}`);
    }
    
    let password = null;
    
    switch (attackType) {
        case 'dictionary':
            password = await cracker.dictionaryAttack(hash, options.hashType);
            break;
        case 'brute':
            password = await cracker.bruteForceAttack(hash, options.hashType, options.maxLength);
            break;
        case 'hybrid':
            password = await cracker.hybridAttack(hash, options.hashType);
            break;
        default:
            console.log('Unknown attack type:', attackType);
            process.exit(1);
    }
    
    if (password) {
        console.log('SUCCESS: Password cracked!');
        console.log(`Hash: ${hash}`);
        console.log(`Password: ${password}`);
    } else {
        console.log('FAILED: Password not cracked');
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = PasswordCracker;
