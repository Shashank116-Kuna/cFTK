"""
Forensic Automation Scripts
Collection of Python scripts for automating common forensic tasks
"""

import os
import sys
import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import csv
import sqlite3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensic_automation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class HashVerification:
    """Script for hash calculation and verification"""
    
    @staticmethod
    def calculate_directory_hashes(directory: str, output_file: str = "hashes.csv"):
        """Calculate hashes for all files in a directory"""
        logger.info(f"Starting hash calculation for directory: {directory}")
        
        results = []
        total_files = 0
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                total_files += 1
                
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()
                        md5_hash = hashlib.md5(data).hexdigest()
                        sha256_hash = hashlib.sha256(data).hexdigest()
                        
                        results.append({
                            'file_path': filepath,
                            'file_name': filename,
                            'size': len(data),
                            'md5': md5_hash,
                            'sha256': sha256_hash,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        logger.info(f"Processed: {filename}")
                        
                except Exception as e:
                    logger.error(f"Error processing {filepath}: {e}")
        
        # Save to CSV
        with open(output_file, 'w', newline='') as csvfile:
            if results:
                writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        
        logger.info(f"Hash calculation complete. Processed {total_files} files.")
        logger.info(f"Results saved to {output_file}")
        
        return results
    
    @staticmethod
    def verify_hashes(hash_file: str, directory: str) -> Dict[str, Any]:
        """Verify file integrity against stored hashes"""
        logger.info(f"Starting hash verification from {hash_file}")
        
        verification_results = {
            'total': 0,
            'matched': 0,
            'mismatched': 0,
            'missing': 0,
            'details': []
        }
        
        # Read stored hashes
        stored_hashes = {}
        with open(hash_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                stored_hashes[row['file_path']] = row
        
        # Verify each file
        for filepath, stored_data in stored_hashes.items():
            verification_results['total'] += 1
            
            if not os.path.exists(filepath):
                verification_results['missing'] += 1
                verification_results['details'].append({
                    'file': filepath,
                    'status': 'MISSING',
                    'message': 'File not found'
                })
                continue
            
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                    current_sha256 = hashlib.sha256(data).hexdigest()
                    
                    if current_sha256 == stored_data['sha256']:
                        verification_results['matched'] += 1
                        verification_results['details'].append({
                            'file': filepath,
                            'status': 'MATCHED',
                            'message': 'Hash verification successful'
                        })
                    else:
                        verification_results['mismatched'] += 1
                        verification_results['details'].append({
                            'file': filepath,
                            'status': 'MISMATCHED',
                            'message': f"Expected: {stored_data['sha256']}, Got: {current_sha256}"
                        })
                        
            except Exception as e:
                logger.error(f"Error verifying {filepath}: {e}")
        
        logger.info(f"Verification complete: {verification_results['matched']} matched, "
                   f"{verification_results['mismatched']} mismatched, "
                   f"{verification_results['missing']} missing")
        
        return verification_results


class MetadataExtractor:
    """Extract metadata from various file types"""
    
    @staticmethod
    def extract_all_metadata(directory: str, output_file: str = "metadata.json"):
        """Extract metadata from all files in directory"""
        logger.info(f"Starting metadata extraction for: {directory}")
        
        metadata_collection = []
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                
                try:
                    stat_info = os.stat(filepath)
                    
                    metadata = {
                        'file_path': filepath,
                        'file_name': filename,
                        'file_size': stat_info.st_size,
                        'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                        'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                        'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                        'permissions': oct(stat_info.st_mode)[-3:],
                        'is_hidden': filename.startswith('.'),
                        'extension': os.path.splitext(filename)[1]
                    }
                    
                    metadata_collection.append(metadata)
                    
                except Exception as e:
                    logger.error(f"Error extracting metadata from {filepath}: {e}")
        
        # Save to JSON
        with open(output_file, 'w') as jsonfile:
            json.dump(metadata_collection, jsonfile, indent=2)
        
        logger.info(f"Metadata extraction complete. Processed {len(metadata_collection)} files.")
        return metadata_collection


class LogParser:
    """Parse and analyze various log file formats"""
    
    @staticmethod
    def parse_apache_logs(log_file: str) -> List[Dict[str, Any]]:
        """Parse Apache/Nginx access logs"""
        logger.info(f"Parsing Apache logs: {log_file}")
        
        parsed_entries = []
        log_pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    import re
                    match = re.match(log_pattern, line)
                    if match:
                        parsed_entries.append({
                            'ip_address': match.group(1),
                            'timestamp': match.group(2),
                            'request': match.group(3),
                            'status_code': int(match.group(4)),
                            'size': int(match.group(5)),
                            'referer': match.group(6),
                            'user_agent': match.group(7)
                        })
        except Exception as e:
            logger.error(f"Error parsing log file: {e}")
        
        logger.info(f"Parsed {len(parsed_entries)} log entries")
        return parsed_entries
    
    @staticmethod
    def analyze_failed_logins(log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze failed login attempts"""
        failed_logins = {}
        
        for entry in log_entries:
            if entry.get('status_code') in [401, 403]:
                ip = entry['ip_address']
                failed_logins[ip] = failed_logins.get(ip, 0) + 1
        
        # Sort by count
        sorted_attempts = sorted(failed_logins.items(), key=lambda x: x[1], reverse=True)
        
        analysis = {
            'total_failed_attempts': sum(failed_logins.values()),
            'unique_ips': len(failed_logins),
            'top_offenders': sorted_attempts[:10],
            'suspicious_ips': [ip for ip, count in sorted_attempts if count > 10]
        }
        
        return analysis


class BrowserArtifactExtractor:
    """Extract artifacts from web browsers"""
    
    @staticmethod
    def extract_chrome_history(profile_path: str) -> List[Dict[str, Any]]:
        """Extract Chrome browsing history"""
        logger.info(f"Extracting Chrome history from: {profile_path}")
        
        history_db = os.path.join(profile_path, 'History')
        if not os.path.exists(history_db):
            logger.error("Chrome History database not found")
            return []
        
        history = []
        
        try:
            # Copy database to avoid locking issues
            import shutil
            temp_db = 'temp_history.db'
            shutil.copy2(history_db, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            query = """
                SELECT url, title, visit_count, last_visit_time 
                FROM urls 
                ORDER BY last_visit_time DESC
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                history.append({
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2],
                    'last_visit': row[3]
                })
            
            conn.close()
            os.remove(temp_db)
            
        except Exception as e:
            logger.error(f"Error extracting Chrome history: {e}")
        
        logger.info(f"Extracted {len(history)} history entries")
        return history
    
    @staticmethod
    def extract_chrome_downloads(profile_path: str) -> List[Dict[str, Any]]:
        """Extract Chrome download history"""
        logger.info(f"Extracting Chrome downloads from: {profile_path}")
        
        history_db = os.path.join(profile_path, 'History')
        downloads = []
        
        try:
            import shutil
            temp_db = 'temp_history.db'
            shutil.copy2(history_db, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            query = """
                SELECT target_path, tab_url, total_bytes, start_time, end_time 
                FROM downloads 
                ORDER BY start_time DESC
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                downloads.append({
                    'file_path': row[0],
                    'source_url': row[1],
                    'size': row[2],
                    'start_time': row[3],
                    'end_time': row[4]
                })
            
            conn.close()
            os.remove(temp_db)
            
        except Exception as e:
            logger.error(f"Error extracting downloads: {e}")
        
        logger.info(f"Extracted {len(downloads)} download entries")
        return downloads


class MalwareDetector:
    """Basic malware detection using signatures and heuristics"""
    
    SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js']
    SUSPICIOUS_STRINGS = ['cmd.exe', 'powershell', 'eval(', 'exec(', 'system(']
    
    @staticmethod
    def scan_directory(directory: str) -> Dict[str, Any]:
        """Scan directory for potential malware"""
        logger.info(f"Starting malware scan: {directory}")
        
        results = {
            'scanned_files': 0,
            'suspicious_files': [],
            'high_risk_files': []
        }
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                results['scanned_files'] += 1
                
                risk_score = 0
                indicators = []
                
                # Check extension
                ext = os.path.splitext(filename)[1].lower()
                if ext in MalwareDetector.SUSPICIOUS_EXTENSIONS:
                    risk_score += 30
                    indicators.append(f"Suspicious extension: {ext}")
                
                # Check file size
                try:
                    size = os.path.getsize(filepath)
                    if size > 10 * 1024 * 1024:  # > 10MB
                        risk_score += 10
                        indicators.append("Large file size")
                except:
                    pass
                
                # Check for suspicious strings
                try:
                    with open(filepath, 'rb') as f:
                        content = f.read(10240).decode('utf-8', errors='ignore')
                        
                        for sus_string in MalwareDetector.SUSPICIOUS_STRINGS:
                            if sus_string in content:
                                risk_score += 20
                                indicators.append(f"Contains: {sus_string}")
                except:
                    pass
                
                if risk_score > 0:
                    file_info = {
                        'filepath': filepath,
                        'risk_score': risk_score,
                        'indicators': indicators
                    }
                    
                    if risk_score >= 50:
                        results['high_risk_files'].append(file_info)
                    else:
                        results['suspicious_files'].append(file_info)
        
        logger.info(f"Scan complete. Found {len(results['suspicious_files'])} suspicious "
                   f"and {len(results['high_risk_files'])} high-risk files")
        
        return results


class TimelineGenerator:
    """Generate forensic timeline from multiple sources"""
    
    @staticmethod
    def generate_filesystem_timeline(directory: str, output_file: str = "timeline.csv"):
        """Generate timeline from filesystem timestamps"""
        logger.info(f"Generating filesystem timeline for: {directory}")
        
        timeline_events = []
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                
                try:
                    stat_info = os.stat(filepath)
                    
                    # Created event
                    timeline_events.append({
                        'timestamp': datetime.fromtimestamp(stat_info.st_ctime),
                        'event_type': 'FILE_CREATED',
                        'source': 'filesystem',
                        'description': f"File created: {filename}",
                        'file_path': filepath
                    })
                    
                    # Modified event
                    timeline_events.append({
                        'timestamp': datetime.fromtimestamp(stat_info.st_mtime),
                        'event_type': 'FILE_MODIFIED',
                        'source': 'filesystem',
                        'description': f"File modified: {filename}",
                        'file_path': filepath
                    })
                    
                except Exception as e:
                    logger.error(f"Error processing {filepath}: {e}")
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        
        # Save to CSV
        with open(output_file, 'w', newline='') as csvfile:
            if timeline_events:
                fieldnames = ['timestamp', 'event_type', 'source', 'description', 'file_path']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for event in timeline_events:
                    event['timestamp'] = event['timestamp'].isoformat()
                    writer.writerow(event)
        
        logger.info(f"Timeline generated with {len(timeline_events)} events")
        return timeline_events


# Main execution
if __name__ == "__main__":
    print("Forensic Automation Scripts")
    print("=" * 50)
    print("\nAvailable Scripts:")
    print("1. Hash Verification")
    print("2. Metadata Extraction")
    print("3. Log Parser")
    print("4. Browser Artifact Extractor")
    print("5. Malware Detector")
    print("6. Timeline Generator")
    print("\nExample usage:")
    print("  python forensic_scripts.py hash /path/to/evidence")
    print("  python forensic_scripts.py metadata /path/to/evidence")
    print("  python forensic_scripts.py scan /path/to/scan")