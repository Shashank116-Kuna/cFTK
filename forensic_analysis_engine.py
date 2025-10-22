"""
Digital Forensic Analysis Engine
Core forensic processing capabilities including file carving, artifact extraction,
and AI-powered analysis
"""

import hashlib
import os
import re
import magic
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import struct

@dataclass
class FileArtifact:
    """Represents a discovered file artifact"""
    id: str
    file_path: str
    file_type: str
    size: int
    md5: str
    sha256: str
    created: Optional[datetime]
    modified: Optional[datetime]
    accessed: Optional[datetime]
    is_deleted: bool
    is_encrypted: bool
    is_hidden: bool
    metadata: Dict[str, Any]
    confidence_score: float

@dataclass
class RegistryArtifact:
    """Windows Registry artifact"""
    key_path: str
    value_name: str
    value_data: Any
    last_modified: datetime
    artifact_type: str
    description: str

@dataclass
class NetworkArtifact:
    """Network-related artifact"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    data_size: int
    flags: List[str]

class ForensicAnalysisEngine:
    """Main forensic analysis engine"""
    
    def __init__(self):
        self.file_signatures = self._load_file_signatures()
        self.artifact_patterns = self._load_artifact_patterns()
        
    def _load_file_signatures(self) -> Dict[str, bytes]:
        """Load common file signatures for file carving"""
        return {
            'jpeg': b'\xFF\xD8\xFF',
            'png': b'\x89\x50\x4E\x47',
            'pdf': b'\x25\x50\x44\x46',
            'zip': b'\x50\x4B\x03\x04',
            'exe': b'\x4D\x5A',
            'elf': b'\x7F\x45\x4C\x46',
            'mp4': b'\x00\x00\x00\x1C\x66\x74\x79\x70',
            'docx': b'\x50\x4B\x03\x04',
            'sqlite': b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33',
        }
    
    def _load_artifact_patterns(self) -> Dict[str, re.Pattern]:
        """Load regex patterns for artifact detection"""
        return {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'url': re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'mac_address': re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'),
        }
    
    def calculate_file_hash(self, file_path: str, algorithm: str = 'both') -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
                if algorithm in ['md5', 'both']:
                    hashes['md5'] = hashlib.md5(data).hexdigest()
                
                if algorithm in ['sha256', 'both']:
                    hashes['sha256'] = hashlib.sha256(data).hexdigest()
                    
                if algorithm == 'sha1':
                    hashes['sha1'] = hashlib.sha1(data).hexdigest()
                    
        except Exception as e:
            hashes['error'] = str(e)
            
        return hashes
    
    def detect_file_type(self, file_path: str) -> Dict[str, Any]:
        """Detect file type using magic numbers and signatures"""
        result = {
            'mime_type': None,
            'extension': None,
            'detected_type': None,
            'is_encrypted': False,
            'is_compressed': False
        }
        
        try:
            # Use python-magic for MIME type detection
            mime = magic.Magic(mime=True)
            result['mime_type'] = mime.from_file(file_path)
            
            # Check file signature
            with open(file_path, 'rb') as f:
                header = f.read(32)
                
                for file_type, signature in self.file_signatures.items():
                    if header.startswith(signature):
                        result['detected_type'] = file_type
                        break
                
                # Check for encryption indicators
                if b'encrypted' in header.lower() or b'aes' in header.lower():
                    result['is_encrypted'] = True
                    
                # Check for compression
                if header.startswith(b'\x1f\x8b') or header.startswith(b'\x50\x4B'):
                    result['is_compressed'] = True
                    
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def carve_files_from_disk_image(self, image_path: str, output_dir: str) -> List[FileArtifact]:
        """File carving from disk image or memory dump"""
        carved_files = []
        
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
                
                # Search for file signatures
                for file_type, signature in self.file_signatures.items():
                    offset = 0
                    while True:
                        offset = data.find(signature, offset)
                        if offset == -1:
                            break
                        
                        # Extract potential file
                        carved_data = self._extract_file_data(data, offset, file_type)
                        if carved_data:
                            output_path = os.path.join(output_dir, f"carved_{file_type}_{offset}.bin")
                            
                            with open(output_path, 'wb') as out:
                                out.write(carved_data)
                            
                            # Create artifact
                            artifact = FileArtifact(
                                id=f"carved_{offset}",
                                file_path=output_path,
                                file_type=file_type,
                                size=len(carved_data),
                                md5=hashlib.md5(carved_data).hexdigest(),
                                sha256=hashlib.sha256(carved_data).hexdigest(),
                                created=None,
                                modified=None,
                                accessed=None,
                                is_deleted=True,
                                is_encrypted=False,
                                is_hidden=False,
                                metadata={'offset': offset},
                                confidence_score=0.8
                            )
                            carved_files.append(artifact)
                        
                        offset += 1
                        
        except Exception as e:
            print(f"Error during file carving: {e}")
            
        return carved_files
    
    def _extract_file_data(self, data: bytes, offset: int, file_type: str) -> Optional[bytes]:
        """Extract file data based on file type"""
        # Simplified extraction - in production, use proper file format parsers
        max_size = 10 * 1024 * 1024  # 10MB max
        
        if file_type in ['jpeg', 'jpg']:
            end_marker = b'\xFF\xD9'
            end_pos = data.find(end_marker, offset)
            if end_pos != -1:
                return data[offset:end_pos + 2]
        
        elif file_type == 'png':
            end_marker = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
            end_pos = data.find(end_marker, offset)
            if end_pos != -1:
                return data[offset:end_pos + 8]
        
        # Default: extract fixed size
        return data[offset:offset + min(max_size, len(data) - offset)]
    
    def extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary file"""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
                # Extract ASCII strings
                ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
                ascii_strings = re.findall(ascii_pattern, data)
                strings.extend([s.decode('ascii') for s in ascii_strings])
                
                # Extract Unicode strings
                unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
                unicode_strings = re.findall(unicode_pattern, data)
                strings.extend([s.decode('utf-16-le', errors='ignore') for s in unicode_strings])
                
        except Exception as e:
            print(f"Error extracting strings: {e}")
            
        return strings
    
    def find_artifacts_in_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        """Search for artifacts in extracted strings"""
        artifacts = defaultdict(list)
        
        for string in strings:
            for artifact_type, pattern in self.artifact_patterns.items():
                matches = pattern.findall(string)
                if matches:
                    artifacts[artifact_type].extend(matches)
        
        # Remove duplicates
        for key in artifacts:
            artifacts[key] = list(set(artifacts[key]))
            
        return dict(artifacts)
    
    def analyze_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract and analyze file metadata"""
        metadata = {
            'file_name': os.path.basename(file_path),
            'file_size': 0,
            'timestamps': {},
            'attributes': [],
            'permissions': None
        }
        
        try:
            stat_info = os.stat(file_path)
            metadata['file_size'] = stat_info.st_size
            metadata['timestamps'] = {
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat()
            }
            metadata['permissions'] = oct(stat_info.st_mode)[-3:]
            
            # Detect hidden files
            if os.path.basename(file_path).startswith('.'):
                metadata['attributes'].append('hidden')
                
        except Exception as e:
            metadata['error'] = str(e)
            
        return metadata
    
    def detect_anti_forensics(self, file_path: str) -> Dict[str, Any]:
        """Detect anti-forensic techniques"""
        indicators = {
            'timestamp_manipulation': False,
            'file_wiping': False,
            'steganography': False,
            'encryption': False,
            'obfuscation': False,
            'details': []
        }
        
        try:
            stat_info = os.stat(file_path)
            
            # Check for suspicious timestamp patterns
            created = datetime.fromtimestamp(stat_info.st_ctime)
            modified = datetime.fromtimestamp(stat_info.st_mtime)
            accessed = datetime.fromtimestamp(stat_info.st_atime)
            
            if created > modified or accessed < modified:
                indicators['timestamp_manipulation'] = True
                indicators['details'].append("Suspicious timestamp ordering detected")
            
            # Check file content for wiping patterns
            with open(file_path, 'rb') as f:
                sample = f.read(4096)
                
                # Check for null bytes (common in wiping)
                null_ratio = sample.count(b'\x00') / len(sample) if sample else 0
                if null_ratio > 0.9:
                    indicators['file_wiping'] = True
                    indicators['details'].append("High ratio of null bytes detected")
                
                # Check entropy for encryption/steganography
                entropy = self._calculate_entropy(sample)
                if entropy > 7.5:
                    indicators['encryption'] = True
                    indicators['steganography'] = True
                    indicators['details'].append(f"High entropy ({entropy:.2f}) suggests encryption or steganography")
                    
        except Exception as e:
            indicators['error'] = str(e)
            
        return indicators
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        byte_counts = defaultdict(int)
        
        for byte in data:
            byte_counts[byte] += 1
        
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * (probability and (probability).bit_length() - 1)
        
        return entropy / 8.0  # Normalize to 0-8 range
    
    def create_timeline(self, artifacts: List[FileArtifact]) -> List[Dict[str, Any]]:
        """Create forensic timeline from artifacts"""
        timeline_events = []
        
        for artifact in artifacts:
            # Add creation event
            if artifact.created:
                timeline_events.append({
                    'timestamp': artifact.created,
                    'event_type': 'file_created',
                    'artifact_id': artifact.id,
                    'description': f"File created: {artifact.file_path}",
                    'metadata': asdict(artifact)
                })
            
            # Add modification event
            if artifact.modified:
                timeline_events.append({
                    'timestamp': artifact.modified,
                    'event_type': 'file_modified',
                    'artifact_id': artifact.id,
                    'description': f"File modified: {artifact.file_path}",
                    'metadata': asdict(artifact)
                })
            
            # Add access event
            if artifact.accessed:
                timeline_events.append({
                    'timestamp': artifact.accessed,
                    'event_type': 'file_accessed',
                    'artifact_id': artifact.id,
                    'description': f"File accessed: {artifact.file_path}",
                    'metadata': asdict(artifact)
                })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        return timeline_events
    
    def analyze_memory_dump(self, dump_path: str) -> Dict[str, Any]:
        """Analyze memory dump for artifacts"""
        results = {
            'processes': [],
            'network_connections': [],
            'loaded_modules': [],
            'strings_found': {},
            'suspicious_indicators': []
        }
        
        try:
            # Extract strings from memory
            strings = self.extract_strings(dump_path, min_length=6)
            results['strings_found'] = self.find_artifacts_in_strings(strings[:10000])
            
            # Look for suspicious patterns
            suspicious_keywords = ['password', 'credential', 'token', 'api_key', 'private_key']
            for keyword in suspicious_keywords:
                matches = [s for s in strings if keyword.lower() in s.lower()]
                if matches:
                    results['suspicious_indicators'].append({
                        'type': 'sensitive_data',
                        'keyword': keyword,
                        'count': len(matches),
                        'samples': matches[:5]
                    })
        
        except Exception as e:
            results['error'] = str(e)
        
        return results


class AIForensicAnalyzer:
    """AI/ML-powered forensic analysis"""
    
    def __init__(self):
        self.artifact_classifier = None
        self.anomaly_detector = None
        
    def classify_artifact(self, artifact: FileArtifact) -> Dict[str, Any]:
        """Classify artifact using ML model"""
        # Placeholder for ML classification
        # In production: use trained models (scikit-learn, TensorFlow, PyTorch)
        
        classification = {
            'category': 'unknown',
            'subcategory': None,
            'confidence': 0.0,
            'tags': [],
            'risk_score': 0.0
        }
        
        # Rule-based classification (replace with ML model)
        if artifact.file_type in ['exe', 'dll', 'so']:
            classification['category'] = 'executable'
            classification['risk_score'] = 0.7
        elif artifact.file_type in ['jpeg', 'png', 'gif']:
            classification['category'] = 'image'
            classification['risk_score'] = 0.2
        elif artifact.file_type in ['pdf', 'doc', 'docx']:
            classification['category'] = 'document'
            classification['risk_score'] = 0.4
        elif artifact.is_encrypted:
            classification['category'] = 'encrypted'
            classification['risk_score'] = 0.8
            
        if artifact.is_hidden:
            classification['tags'].append('hidden')
            classification['risk_score'] += 0.2
            
        if artifact.is_deleted:
            classification['tags'].append('deleted')
            classification['risk_score'] += 0.1
            
        classification['confidence'] = 0.85
        return classification
    
    def detect_anomalies(self, artifacts: List[FileArtifact]) -> List[Dict[str, Any]]:
        """Detect anomalous artifacts using ML"""
        anomalies = []
        
        # Statistical anomaly detection
        file_sizes = [a.size for a in artifacts]
        if file_sizes:
            mean_size = sum(file_sizes) / len(file_sizes)
            std_size = (sum((x - mean_size) ** 2 for x in file_sizes) / len(file_sizes)) ** 0.5
            
            for artifact in artifacts:
                z_score = abs((artifact.size - mean_size) / std_size) if std_size > 0 else 0
                
                if z_score > 3:  # More than 3 standard deviations
                    anomalies.append({
                        'artifact_id': artifact.id,
                        'anomaly_type': 'unusual_file_size',
                        'score': z_score,
                        'details': f"File size {artifact.size} bytes is unusual"
                    })
        
        # Temporal anomaly detection
        timestamps = [(a.modified, a) for a in artifacts if a.modified]
        timestamps.sort(key=lambda x: x[0])
        
        for i in range(len(timestamps) - 1):
            time_diff = (timestamps[i+1][0] - timestamps[i][0]).total_seconds()
            if time_diff < 1:  # Files modified within 1 second
                anomalies.append({
                    'artifact_id': timestamps[i][1].id,
                    'anomaly_type': 'rapid_modification',
                    'score': 0.8,
                    'details': 'Multiple files modified in rapid succession'
                })
        
        return anomalies
    
    def predict_user_activity(self, artifacts: List[FileArtifact]) -> Dict[str, Any]:
        """Predict user activities from artifacts"""
        activities = {
            'web_browsing': 0.0,
            'document_editing': 0.0,
            'file_transfer': 0.0,
            'media_consumption': 0.0,
            'system_administration': 0.0
        }
        
        for artifact in artifacts:
            # Simple rule-based prediction (replace with ML model)
            if 'browser' in artifact.file_path.lower() or 'cache' in artifact.file_path.lower():
                activities['web_browsing'] += 0.1
            elif artifact.file_type in ['doc', 'docx', 'pdf', 'txt']:
                activities['document_editing'] += 0.1
            elif artifact.file_type in ['zip', 'rar', 'tar']:
                activities['file_transfer'] += 0.1
            elif artifact.file_type in ['mp4', 'mp3', 'avi']:
                activities['media_consumption'] += 0.1
            elif 'system' in artifact.file_path.lower():
                activities['system_administration'] += 0.1
        
        # Normalize scores
        total = sum(activities.values())
        if total > 0:
            activities = {k: min(v / total, 1.0) for k, v in activities.items()}
        
        return activities


# Example usage functions
def analyze_evidence_file(file_path: str) -> Dict[str, Any]:
    """Complete analysis of an evidence file"""
    engine = ForensicAnalysisEngine()
    ai_analyzer = AIForensicAnalyzer()
    
    results = {
        'file_path': file_path,
        'timestamp': datetime.utcnow().isoformat(),
        'analysis': {}
    }
    
    # Hash calculation
    results['analysis']['hashes'] = engine.calculate_file_hash(file_path)
    
    # File type detection
    results['analysis']['file_type'] = engine.detect_file_type(file_path)
    
    # Metadata extraction
    results['analysis']['metadata'] = engine.analyze_metadata(file_path)
    
    # String extraction and artifact detection
    strings = engine.extract_strings(file_path)
    results['analysis']['artifacts_found'] = engine.find_artifacts_in_strings(strings)
    results['analysis']['string_count'] = len(strings)
    
    # Anti-forensics detection
    results['analysis']['anti_forensics'] = engine.detect_anti_forensics(file_path)
    
    return results


if __name__ == "__main__":
    # Example usage
    print("Digital Forensic Analysis Engine")
    print("=" * 50)
    
    engine = ForensicAnalysisEngine()
    ai_analyzer = AIForensicAnalyzer()
    
    # Example: Analyze a file
    # results = analyze_evidence_file("/path/to/evidence/file.bin")
    # print(json.dumps(results, indent=2))
    
    print("\nEngine initialized successfully")
    print(f"Loaded {len(engine.file_signatures)} file signatures")
    print(f"Loaded {len(engine.artifact_patterns)} artifact patterns")