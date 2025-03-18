#!/usr/bin/env python3

import os
import sys
import hashlib
import logging
import tempfile
import argparse
from pathlib import Path
from typing import Optional, List, Dict
import requests
import zipfile
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('updater.log')
    ]
)
logger = logging.getLogger(__name__)

class DownloadError(Exception):
    """Custom exception for download failures"""
    pass

class ExtractionError(Exception):
    """Custom exception for extraction failures"""
    pass

class HashingError(Exception):
    """Custom exception for hashing failures"""
    pass

class MoodleDownloader:
    """Handles downloading of Moodle versions"""
    
    DOWNLOAD_BASE = "https://download.moodle.org"
    STABLE_PATH = "/download.php/stable{major_version_path}/moodle-{version}.{ext}"
    DIRECT_PATH = "/download.php/direct/stable{major_version_path}/moodle-{version}.{ext}"
    SHA_URL = f"{DOWNLOAD_BASE}/download.php/direct/stable{{major_version_path}}/moodle-{{version}}.{{ext}}.sha256"
    VERSION_CHECK_URLS = [
        f"{DOWNLOAD_BASE}/releases/latest/",
        f"{DOWNLOAD_BASE}/releases/supported/",
        f"{DOWNLOAD_BASE}/releases/security/",
        f"{DOWNLOAD_BASE}/releases/legacy/"
    ]
    
    def __init__(self, version: str):
        self.version = version
        self.major_version = '.'.join(version.split('.')[:2])
        # Convert 4.5.3 to 405 for the URL path
        major_parts = self.major_version.split('.')
        self.major_version_path = f"{major_parts[0]}0{major_parts[1]}"

    def get_download_url(self, ext: str, direct: bool = False) -> str:
        """Get the download URL for a specific format"""
        path = self.DIRECT_PATH if direct else self.STABLE_PATH
        return self.DOWNLOAD_BASE + path.format(
            major_version_path=self.major_version_path,
            version=self.version,
            ext=ext
        )
    
    def verify_version_exists(self) -> bool:
        """Verify if the Moodle version exists before attempting download"""
        logger.info(f"Verifying Moodle version {self.version} exists")
        
        # First check the version listings
        try:
            for check_url in self.VERSION_CHECK_URLS:
                response = requests.get(check_url)
                response.raise_for_status()
                if f"Moodle {self.version}" in response.text:
                    logger.info(f"Found version {self.version} in listings")
                    return True
        except requests.exceptions.RequestException:
            pass

        # Then try SHA files which should exist for valid versions
        try:
            for ext in ['zip', 'tgz']:
                url = self.SHA_URL.format(
                    major_version_path=self.major_version_path,
                    version=self.version,
                    ext=ext
                )
                response = requests.head(url)
                if response.status_code == 200:
                    logger.info(f"Found SHA file for version {self.version} ({ext})")
                    return True
        except requests.exceptions.RequestException:
            pass

        logger.error(f"Moodle version {self.version} not found")
        return False

    def download_file(self, url: str, target_file: Path, timeout: int = 300) -> bool:
        """Download a file with timeout and checks"""
        try:
            # First try direct download
            response = requests.get(url, stream=True, timeout=timeout)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' in content_type:
                return False
            
            if not any(t in content_type for t in ['zip', 'gzip', 'octet-stream', 'application/x-gzip']):
                return False
            
            logger.info(f"Downloading file from {url}")
            with open(target_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
            
        except requests.exceptions.RequestException:
            return False
        
    def download(self, target_dir: Path) -> Path:
        """Download Moodle version to target directory"""
        # First verify the version exists
        if not self.verify_version_exists():
            raise DownloadError(f"Moodle version {self.version} not found or not accessible")
        
        # Try both zip and tgz formats
        errors = []
        for ext in ['zip', 'tgz']:
            target_file = target_dir / f"moodle-{self.version}.{ext}"
            
            # First try direct download URL
            direct_url = self.get_download_url(ext, direct=True)
            logger.info(f"Attempting direct download from {direct_url}")
            if self.download_file(direct_url, target_file):
                logger.info(f"Successfully downloaded to {target_file}")
                return target_file
            
            # If direct fails, try the regular download URL
            regular_url = self.get_download_url(ext, direct=False)
            logger.info(f"Attempting regular download from {regular_url}")
            if self.download_file(regular_url, target_file):
                logger.info(f"Successfully downloaded to {target_file}")
                return target_file
            
            errors.append(f"{ext}: Failed both direct and regular download attempts")
        
        error_details = "\n".join(errors)
        raise DownloadError(f"Failed to download Moodle {self.version} in any format:\n{error_details}")

class MoodleExtractor:
    """Handles extraction of Moodle archives"""
    
    def extract(self, archive_path: Path, target_dir: Path) -> Path:
        """Extract Moodle archive (ZIP or TGZ)"""
        logger.info(f"Extracting {archive_path} to {target_dir}")
        
        try:
            if archive_path.suffix == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(target_dir)
            elif archive_path.suffix == '.tgz':
                import tarfile
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(target_dir)
            else:
                raise ExtractionError(f"Unsupported archive format: {archive_path.suffix}")
                
            # The extracted directory will be named 'moodle'
            extracted_dir = target_dir / 'moodle'
            if not extracted_dir.exists():
                raise ExtractionError(f"Expected 'moodle' directory not found in extracted archive")
                
            logger.info(f"Successfully extracted to {extracted_dir}")
            return extracted_dir
            
        except (zipfile.BadZipFile, tarfile.TarError) as e:
            raise ExtractionError(f"Failed to extract corrupt archive: {str(e)}")
        except Exception as e:
            raise ExtractionError(f"Failed to extract archive: {str(e)}")

class FileHasher:
    """Handles file hashing operations"""
    
    def __init__(self, algorithm: str = 'sha256'):
        self.algorithm = algorithm
        
    def compute_hash(self, file_path: Path) -> str:
        """Compute hash for a single file"""
        try:
            hash_obj = hashlib.new(self.algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            raise HashingError(f"Failed to hash {file_path}: {str(e)}")
            
    def hash_directory(self, directory: Path) -> Dict[str, str]:
        """Hash all files in directory recursively"""
        results = {}
        
        with ThreadPoolExecutor() as executor:
            future_to_path = {}
            
            for file_path in directory.rglob('*'):
                if file_path.is_file():
                    future = executor.submit(self.compute_hash, file_path)
                    future_to_path[future] = file_path
                    
            for future in as_completed(future_to_path):
                file_path = future_to_path[future]
                try:
                    file_hash = future.result()
                    # Store relative path with forward slashes
                    relative_path = str(file_path.relative_to(directory)).replace(os.sep, '/')
                    results[relative_path] = file_hash
                except Exception as e:
                    logger.warning(f"Failed to hash {file_path}: {str(e)}")
                    
        return results

class VersionFileUpdater:
    """Handles updating the version.txt file"""
    
    def __init__(self, output_path: Path):
        self.output_path = output_path
        
    def update(self, version: str, hash_results: Dict[str, str]):
        """Update version.txt with new entries"""
        logger.info(f"Updating {self.output_path} with version {version}")
        
        try:
            with open(self.output_path, 'a') as f:
                for file_path, file_hash in sorted(hash_results.items()):
                    entry = f"{version};{file_hash};/{file_path}\n"
                    f.write(entry)
                    
            logger.info(f"Successfully updated {self.output_path}")
            
        except Exception as e:
            logger.error(f"Failed to update {self.output_path}: {str(e)}")
            raise

class MoodleVersionUpdater:
    """Main class orchestrating the update process"""
    
    def __init__(self, version: str, output_path: Path):
        self.version = version
        self.output_path = output_path
        self.downloader = MoodleDownloader(version)
        self.extractor = MoodleExtractor()
        self.hasher = FileHasher()
        self.updater = VersionFileUpdater(output_path)
        
    def update(self):
        """Run the complete update process"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Download Moodle
                zip_path = self.downloader.download(temp_path)
                
                # Extract archive
                moodle_dir = self.extractor.extract(zip_path, temp_path)
                
                # Compute hashes
                hash_results = self.hasher.hash_directory(moodle_dir)
                
                # Update version.txt
                self.updater.update(self.version, hash_results)
                
                logger.info("Update process completed successfully")
                
            except (DownloadError, ExtractionError, HashingError) as e:
                logger.error(f"Update process failed: {str(e)}")
                raise
            except Exception as e:
                logger.error(f"Unexpected error during update: {str(e)}")
                raise

def main():
    parser = argparse.ArgumentParser(description="Update Moodle version.txt")
    parser.add_argument('version', help="Moodle version number (e.g., 4.0.3)")
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('version.txt'),
        help="Output version.txt path"
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help="Set logging level"
    )
    
    args = parser.parse_args()
    
    # Update log level if specified
    logging.getLogger().setLevel(args.log_level)
    
    try:
        updater = MoodleVersionUpdater(args.version, args.output)
        updater.update()
    except Exception as e:
        logger.error(f"Failed to update version.txt: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 