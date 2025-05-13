#!/usr/bin/env python3

import os
import re
import sys
from pathlib import Path

OLD_AUTH_LIBRARY_IMPORT_BASE = "github.com/rokwire/core-auth-library-go/v3/"
OLD_LOGGING_LIBRARY_IMPORT_BASE = "github.com/rokwire/logging-library-go/v2/"
SDK_IMPORT_BASE = "github.com/rokwire/rokwire-building-block-sdk-go/"

# Mapping of old import paths to new SDK structure
AUTH_IMPORT_MAPPING = {
    'tokenauth': 'services/core/auth/tokenauth',
    'webauth': 'services/core/auth/webauth',
    'keys': 'services/core/auth/keys',
    'sigauth': 'services/core/auth/sigauth',
    'authservice': 'services/core/auth',
    'authutils': 'utils/rokwireutils',
    'coreservice': 'services/core',
    'envloader': 'utils/envloader',
    'authorization': 'services/core/auth/authorization'
}

LOGGING_IMPORT_MAPPING = {
    'errors': 'utils/errors',
    'logutils': 'utils/logging/logutils',
    'logs': 'utils/logging/logs'
}

REFERENCE_MAPPING = {
    "authutils.": "rokwireutils.",
    "authservice.AuthService": "auth.Service",
    "authservice.": "auth.",
    "coreservice.": "core.",
}

def process_references(content):
    """Replace references to old imports in the code."""
    # Sort reference mappings by length (longest first) to handle more specific cases first
    sorted_refs = sorted(REFERENCE_MAPPING.items(), key=lambda x: len(x[0]), reverse=True)
    
    # Process each reference mapping
    for old_ref, new_ref in sorted_refs:
        # Escape special characters in the old reference for regex
        escaped_old_ref = re.escape(old_ref)
        # Replace the reference while preserving case
        content = re.sub(escaped_old_ref, new_ref, content)
    
    return content

def process_dockerfile_paths(content):
    """Process Dockerfile COPY commands to update auth library paths."""
    old_vendor_path = f'/app/vendor/{OLD_AUTH_LIBRARY_IMPORT_BASE.rstrip("/")}'
    new_vendor_path = f'/app/vendor/{SDK_IMPORT_BASE.rstrip("/")}'
    
    pattern = fr'(COPY --from=\w+ )({re.escape(old_vendor_path)}\/)([^\s]+)(\s+)({re.escape(old_vendor_path)}\/)([^\s]+)'
    
    def replace_path(match):
        prefix = match.group(1)
        path1 = match.group(3)
        spacer = match.group(4)
        path2 = match.group(6)
        
        # Find the new path in AUTH_IMPORT_MAPPING
        new_path1 = path1
        new_path2 = path2
        for old_prefix, new_prefix in AUTH_IMPORT_MAPPING.items():
            if path1.startswith(old_prefix):
                new_path1 = path1.replace(old_prefix, new_prefix, 1)
            if path2.startswith(old_prefix):
                new_path2 = path2.replace(old_prefix, new_prefix, 1)
        
        return f'{prefix}{new_vendor_path}/{new_path1}{spacer}{new_vendor_path}/{new_path2}'
    
    return re.sub(pattern, replace_path, content)

def process_file(file_path):
    """Process a single file and update its imports and references."""
    with open(file_path, 'r') as f:
        content = f.read()

    # Handle Dockerfile specific changes
    if file_path.endswith('Dockerfile'):
        content = process_dockerfile_paths(content)
        with open(file_path, 'w') as f:
            f.write(content)
        return

    # Handle Go files
    if not file_path.endswith('.go'):
        return

    # First, process all import blocks
    import_blocks = re.finditer(r'(import\s*\()(.*?)(\))', content, re.DOTALL)
    
    for block in import_blocks:
        import_block = block.group(2)
        import_lines = import_block.split('\n')
        new_imports = []
        
        # Process each import line while preserving spacing
        for line in import_lines:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith('//'):
                new_imports.append(line)  # Keep original line including whitespace
                continue
            
            # Extract the import path
            match = re.match(r'"(.*?)"', stripped_line)
            if not match:
                new_imports.append(line)  # Keep original line including whitespace
                continue
            
            old_path = match.group(1)
            new_path = None

            # Check if it's an auth library import
            if old_path.startswith(OLD_AUTH_LIBRARY_IMPORT_BASE):
                relative_path = old_path[len(OLD_AUTH_LIBRARY_IMPORT_BASE):]
                for old_prefix, new_prefix in AUTH_IMPORT_MAPPING.items():
                    if relative_path.startswith(old_prefix):
                        new_path = SDK_IMPORT_BASE + relative_path.replace(old_prefix, new_prefix, 1)
                        break

            # Check if it's a logging library import
            elif old_path.startswith(OLD_LOGGING_LIBRARY_IMPORT_BASE):
                relative_path = old_path[len(OLD_LOGGING_LIBRARY_IMPORT_BASE):]
                for old_prefix, new_prefix in LOGGING_IMPORT_MAPPING.items():
                    if relative_path.startswith(old_prefix):
                        new_path = SDK_IMPORT_BASE + relative_path.replace(old_prefix, new_prefix, 1)
                        break

            if new_path:
                # Preserve the original indentation and alias if present
                alias_match = re.match(r'(\s*)(\w+\s+)?', line)
                indent = alias_match.group(1)
                alias = alias_match.group(2) or ''
                new_imports.append(f'{indent}{alias}"{new_path}"')
            else:
                new_imports.append(line)  # Keep original line including whitespace
        
        # Replace the old import block with the new one, preserving the original structure
        new_block = block.group(1) + '\n'.join(new_imports) + block.group(3)
        content = content[:block.start()] + new_block + content[block.end():]
    
    # Then, process all references in the code
    content = process_references(content)
    
    # Write the updated content back to the file
    with open(file_path, 'w') as f:
        f.write(content)

def main():
    target_dir = '.'
    
    # Process all .go files and Dockerfiles in the directory and its subdirectories
    for root, _, files in os.walk(target_dir):
        # Skip vendor directory and its contents
        if 'vendor' in root.split(os.sep):
            continue
            
        for file in files:
            if file.endswith('.go') or file == 'Dockerfile':
                file_path = os.path.join(root, file)
                print(f"Processing {file_path}...")
                process_file(file_path)

if __name__ == '__main__':
    main()