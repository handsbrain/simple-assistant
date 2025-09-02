#!/usr/bin/env python3
"""
Test script to validate attachment processing functionality.
This script tests the attachment processing without requiring email access.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the current directory to the path so we can import from email_worker
sys.path.insert(0, str(Path(__file__).parent))

def test_attachment_validation():
    """Test the attachment validation function."""
    print("Testing attachment validation...")
    
    try:
        from email_worker import validate_attachment_processing
        results = validate_attachment_processing()
        
        print("Validation Results:")
        for key, value in results.items():
            if key != "errors":
                print(f"  {key}: {value}")
        
        if results["errors"]:
            print("  Errors:")
            for error in results["errors"]:
                print(f"    - {error}")
        else:
            print("  No errors found!")
            
        return len(results["errors"]) == 0
        
    except Exception as e:
        print(f"Error testing validation: {type(e).__name__}: {e}")
        return False

def test_text_extraction():
    """Test text extraction from a sample DOCX file."""
    print("\nTesting text extraction...")
    
    try:
        from email_worker import _extract_text_from_attachment
        
        # Check if we have the sample DOCX file
        sample_file = Path("attach_probe_out/Description_Iraq_Rig T-80 National 2000 HP .docx")
        if not sample_file.exists():
            print(f"Sample file not found: {sample_file}")
            return False
        
        # Read the file
        with open(sample_file, "rb") as f:
            data = f.read()
        
        print(f"Testing with file: {sample_file.name}")
        print(f"File size: {len(data)} bytes")
        
        # Extract text
        text = _extract_text_from_attachment(sample_file.name, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", data)
        
        if text:
            print(f"Successfully extracted {len(text)} characters")
            print("Preview (first 200 chars):")
            print(text[:200] + "..." if len(text) > 200 else text)
            return True
        else:
            print("No text extracted")
            return False
            
    except Exception as e:
        print(f"Error testing text extraction: {type(e).__name__}: {e}")
        return False

def test_file_extension_detection():
    """Test file extension detection."""
    print("\nTesting file extension detection...")
    
    try:
        from email_worker import _file_ext
        
        test_cases = [
            ("document.pdf", "application/pdf", "pdf"),
            ("report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
            ("presentation.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx"),
            ("spreadsheet.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
            ("image.png", "image/png", "png"),
            ("text.txt", "text/plain", "txt"),
        ]
        
        all_passed = True
        for filename, content_type, expected in test_cases:
            result = _file_ext(filename, content_type)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {filename} ({content_type}) -> {result} (expected: {expected})")
            if result != expected:
                all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"Error testing file extension detection: {type(e).__name__}: {e}")
        return False

def main():
    """Run all tests."""
    print("=== Attachment Processing Test Suite ===\n")
    
    tests = [
        ("Attachment Validation", test_attachment_validation),
        ("File Extension Detection", test_file_extension_detection),
        ("Text Extraction", test_text_extraction),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"Running {test_name}...")
        try:
            result = test_func()
            results.append((test_name, result))
            print(f"{test_name}: {'PASSED' if result else 'FAILED'}")
        except Exception as e:
            print(f"{test_name}: ERROR - {type(e).__name__}: {e}")
            results.append((test_name, False))
        print()
    
    # Summary
    print("=== Test Summary ===")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "PASSED" if result else "FAILED"
        print(f"  {test_name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Attachment processing is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
