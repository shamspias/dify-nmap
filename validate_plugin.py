#!/usr/bin/env python3
"""
Plugin validation script to check YAML configurations before packaging.
Run this before creating the .difypkg file to catch configuration errors.
"""

import os
import sys
import yaml
from pathlib import Path


def validate_parameter(param, param_index, tool_name):
    """Validate a single parameter configuration"""
    errors = []
    param_name = param.get('name', f'param_{param_index}')

    # Required fields for all parameters
    required_fields = ['name', 'type', 'label', 'form']

    for field in required_fields:
        if field not in param:
            errors.append(f"  Parameter '{param_name}' missing required field: {field}")

    # Check if human_description is present
    if 'human_description' not in param:
        errors.append(f"  Parameter '{param_name}' missing required field: human_description")

    # If form is 'llm', must have llm_description
    if param.get('form') == 'llm':
        if 'llm_description' not in param:
            errors.append(f"  Parameter '{param_name}' with form='llm' missing required field: llm_description")

    # Validate label has required language
    if 'label' in param:
        if not isinstance(param['label'], dict):
            errors.append(f"  Parameter '{param_name}' label must be a dictionary")
        elif 'en_US' not in param['label']:
            errors.append(f"  Parameter '{param_name}' label missing required language: en_US")

    # Validate human_description has required language
    if 'human_description' in param:
        if not isinstance(param['human_description'], dict):
            errors.append(f"  Parameter '{param_name}' human_description must be a dictionary")
        elif 'en_US' not in param['human_description']:
            errors.append(f"  Parameter '{param_name}' human_description missing required language: en_US")

    return errors


def validate_tool_yaml(yaml_path):
    """Validate a tool YAML configuration file"""
    errors = []

    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        return [f"Failed to parse YAML: {e}"]

    # Check required top-level fields
    required_top = ['identity', 'description', 'parameters']
    for field in required_top:
        if field not in config:
            errors.append(f"Missing required top-level field: {field}")

    # Validate parameters
    if 'parameters' in config:
        if not isinstance(config['parameters'], list):
            errors.append("Parameters must be a list")
        else:
            for i, param in enumerate(config['parameters']):
                param_errors = validate_parameter(param, i, yaml_path.stem)
                errors.extend(param_errors)

    return errors


def validate_provider_yaml(yaml_path):
    """Validate provider YAML configuration"""
    errors = []

    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        return [f"Failed to parse YAML: {e}"]

    # Check required fields
    required = ['identity', 'tools']
    for field in required:
        if field not in config:
            errors.append(f"Missing required field: {field}")

    # Check identity fields
    if 'identity' in config:
        identity_required = ['name', 'author', 'label', 'description']
        for field in identity_required:
            if field not in config['identity']:
                errors.append(f"Missing required identity field: {field}")

    return errors


def validate_manifest(yaml_path):
    """Validate manifest.yaml"""
    errors = []

    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        return [f"Failed to parse YAML: {e}"]

    # Check required fields
    required = ['version', 'type', 'author', 'name', 'label', 'description', 'plugins']
    for field in required:
        if field not in config:
            errors.append(f"Missing required field: {field}")

    return errors


def main():
    """Main validation function"""
    print("🔍 Validating Nmap Scanner Plugin Configuration...")
    print("=" * 60)

    plugin_dir = Path(__file__).parent
    total_errors = 0

    # Validate manifest.yaml
    manifest_path = plugin_dir / 'manifest.yaml'
    if manifest_path.exists():
        print("\n📋 Checking manifest.yaml...")
        errors = validate_manifest(manifest_path)
        if errors:
            print("  ❌ Errors found:")
            for error in errors:
                print(f"    {error}")
            total_errors += len(errors)
        else:
            print("  ✅ Valid")
    else:
        print("  ❌ manifest.yaml not found!")
        total_errors += 1

    # Validate provider YAML files
    provider_dir = plugin_dir / 'provider'
    if provider_dir.exists():
        print("\n📦 Checking provider configurations...")
        for yaml_file in provider_dir.glob('*.yaml'):
            print(f"  Checking {yaml_file.name}...")
            errors = validate_provider_yaml(yaml_file)
            if errors:
                print("    ❌ Errors found:")
                for error in errors:
                    print(f"      {error}")
                total_errors += len(errors)
            else:
                print("    ✅ Valid")

    # Validate tool YAML files
    tools_dir = plugin_dir / 'tools'
    if tools_dir.exists():
        print("\n🔧 Checking tool configurations...")
        for yaml_file in tools_dir.glob('*.yaml'):
            print(f"  Checking {yaml_file.name}...")
            errors = validate_tool_yaml(yaml_file)
            if errors:
                print("    ❌ Errors found:")
                for error in errors:
                    print(f"      {error}")
                total_errors += len(errors)
            else:
                print("    ✅ Valid")

    # Check for required Python files
    print("\n🐍 Checking Python files...")
    required_py = [
        'main.py',
        'provider/nmap_scanner.py',
        'tools/port_scanner.py',
        'tools/network_discovery.py',
        'tools/vulnerability_scanner.py',
        'tools/service_detector.py',
        'tools/os_fingerprint.py'
    ]

    for py_file in required_py:
        py_path = plugin_dir / py_file
        if py_path.exists():
            print(f"  ✅ {py_file} found")
        else:
            print(f"  ❌ {py_file} missing!")
            total_errors += 1

    # Final summary
    print("\n" + "=" * 60)
    if total_errors == 0:
        print("✅ All validations passed! Plugin is ready to package.")
        print("\nTo create the plugin package, run:")
        print(f"  dify plugin package {plugin_dir}")
        return 0
    else:
        print(f"❌ Found {total_errors} error(s). Please fix them before packaging.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
