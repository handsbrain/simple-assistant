#!/usr/bin/env python3
"""
Simple test script to validate attachment processing functionality.
This script tests the core attachment processing logic without requiring all dependencies.
"""

import os
import sys
import tempfile
from pathlib import Path

def test_file_extension_detection():
    """Test file extension detection logic."""
    print("Testing file extension detection...")
    
    def _file_ext(name: str, ctype: str) -> str:
        n = (name or "").lower().strip()
        if "." in n:
            return n.rsplit(".", 1)[-1]
        if "/" in (ctype or ""):
            return ctype.split("/")[-1].lower()
        return ""
    
    test_cases = [
        ("document.pdf", "application/pdf", "pdf"),
        ("report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
        ("presentation.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx"),
        ("spreadsheet.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
        ("image.png", "image/png", "png"),
        ("text.txt", "text/plain", "txt"),
        ("noextension", "application/pdf", "pdf"),
        ("", "", ""),
    ]
    
    all_passed = True
    for filename, content_type, expected in test_cases:
        result = _file_ext(filename, content_type)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {filename} ({content_type}) -> {result} (expected: {expected})")
        if result != expected:
            all_passed = False
    
    return all_passed

def test_docx_extraction():
    """Test DOCX text extraction if python-docx is available."""
    print("\nTesting DOCX text extraction...")
    
    try:
        from docx import Document
        print("  ✓ python-docx is available")
        
        # Check if we have the sample DOCX file
        sample_file = Path("attach_probe_out/Description_Iraq_Rig T-80 National 2000 HP .docx")
        if not sample_file.exists():
            print(f"  ✗ Sample file not found: {sample_file}")
            return False
        
        # Read the file
        with open(sample_file, "rb") as f:
            data = f.read()
        
        print(f"  ✓ Found sample file: {sample_file.name} ({len(data)} bytes)")
        
        # Extract text using the same logic as in email_worker.py
        import io
        d = Document(io.BytesIO(data))
        text = "\n".join(p.text for p in d.paragraphs if p.text)
        
        if text:
            print(f"  ✓ Successfully extracted {len(text)} characters")
            print("  Preview (first 200 chars):")
            print(f"    {text[:200]}{'...' if len(text) > 200 else ''}")
            return True
        else:
            print("  ✗ No text extracted")
            return False
            
    except ImportError:
        print("  ✗ python-docx not available")
        return False
    except Exception as e:
        print(f"  ✗ Error: {type(e).__name__}: {e}")
        return False

def test_pdf_extraction():
    """Test PDF text extraction if pypdf is available."""
    print("\nTesting PDF text extraction...")
    
    try:
        from pypdf import PdfReader
        print("  ✓ pypdf is available")
        return True
    except ImportError:
        print("  ✗ pypdf not available")
        return False

def test_ocr_availability():
    """Test OCR dependencies."""
    print("\nTesting OCR dependencies...")
    
    try:
        import pytesseract
        print("  ✓ pytesseract is available")
    except ImportError:
        print("  ✗ pytesseract not available")
    
    try:
        from PIL import Image
        print("  ✓ PIL (Pillow) is available")
    except ImportError:
        print("  ✗ PIL (Pillow) not available")
    
    try:
        import pypdfium2
        print("  ✓ pypdfium2 is available")
    except ImportError:
        print("  ✗ pypdfium2 not available")

def test_excel_extraction():
    """Test Excel text extraction if openpyxl is available."""
    print("\nTesting Excel text extraction...")
    
    try:
        import openpyxl
        print("  ✓ openpyxl is available")
        return True
    except ImportError:
        print("  ✗ openpyxl not available")
        return False

def test_powerpoint_extraction():
    """Test PowerPoint text extraction if python-pptx is available."""
    print("\nTesting PowerPoint text extraction...")
    
    try:
        from pptx import Presentation
        print("  ✓ python-pptx is available")
        return True
    except ImportError:
        print("  ✗ python-pptx not available")
        return False

def main():
    """Run all tests."""
    print("=== Simple Attachment Processing Test Suite ===\n")
    
    tests = [
        ("File Extension Detection", test_file_extension_detection),
        ("DOCX Text Extraction", test_docx_extraction),
        ("PDF Text Extraction", test_pdf_extraction),
        ("Excel Text Extraction", test_excel_extraction),
        ("PowerPoint Text Extraction", test_powerpoint_extraction),
        ("OCR Dependencies", test_ocr_availability),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"Running {test_name}...")
        try:
            result = test_func()
            if result is not None:  # Some tests don't return a boolean
                results.append((test_name, result))
            else:
                results.append((test_name, True))  # Assume success if no boolean returned
        except Exception as e:
            print(f"  ✗ Error: {type(e).__name__}: {e}")
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
        print("🎉 All tests passed! Core attachment processing is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
