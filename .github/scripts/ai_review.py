#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from anthropic import Anthropic

def get_base_ref():
    """Base branch to diff against (e.g. main, master). Set by workflow or default to main."""
    return os.environ.get('BASE_REF', 'main')

def get_diff():
    """Get the PR diff"""
    base = get_base_ref()
    result = subprocess.run(
        ['git', 'diff', f'origin/{base}...HEAD'],
        capture_output=True,
        text=True
    )
    return result.stdout

def get_changed_files():
    """Get list of changed Swift files"""
    base = get_base_ref()
    result = subprocess.run(
        ['git', 'diff', '--name-only', f'origin/{base}...HEAD'],
        capture_output=True,
        text=True
    )
    files = result.stdout.strip().split('\n')
    return [f for f in files if f.endswith('.swift') or f.endswith('.md')]

def get_file_content(filepath):
    """Get content of a specific file"""
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except:
        return None

def review_code(diff, changed_files, file_contents):
    """Send code to Claude for review"""
    client = Anthropic(api_key=os.environ['ANTHROPIC_API_KEY'])
    
    # Build context
    files_context = "\n\n".join([
        f"File: {filepath}\n```swift\n{content}\n```"
        for filepath, content in file_contents.items()
        if content
    ])
    
    prompt = f"""You are performing an adversarial code review for an mDL (mobile driver's license) wallet app written in Swift.

This code may have been generated or suggested by AI tools like Cursor. Your job is to find potential issues that an AI might miss or introduce.

# Changed Files Context:
{files_context}

# Git Diff:
```diff
{diff}
```

# Review Guidelines:

## Security (CRITICAL for mDL wallet):
- Are cryptographic operations using CryptoKit correctly?
- Are private keys stored only in Keychain, never in UserDefaults or files?
- Are there any hardcoded secrets or test keys?
- Is sensitive data being logged?
- Are there timing attack vulnerabilities in crypto code?
- Is input validation thorough for all external data?

## Swift Best Practices:
- Are optionals handled safely (no force unwrapping without justification)?
- Is error handling appropriate (Result vs throws)?
- Are structs used for data models (value semantics)?
- Are actors used correctly for mutable shared state?
- Is Sendable conformance correct?
- Are there any retain cycles (@weak, @unowned)?

## ISO 18013-5 Compliance:
- Does CBOR encoding/decoding follow the spec?
- Are data elements named correctly per the standard?
- Is device engagement implemented correctly?
- Are security requirements from the spec followed?

## Testing:
- Are there tests for the changed code?
- Are edge cases covered?
- Are error conditions tested?
- Are crypto operations using test keys (not real keys)?

## Code Quality:
- Is the code overly complex where simpler would work?
- Are there duplicated patterns that should be abstracted?
- Are naming conventions followed?
- Is there adequate documentation?
- Are there any "AI-isms" (overly verbose, unnecessary abstractions)?

# Output Format:

Provide your review in this JSON format:
{{
  "summary": "Brief overview of findings",
  "severity": "critical|high|medium|low",
  "issues": [
    {{
      "file": "path/to/file.swift",
      "line": 42,
      "severity": "critical|high|medium|low",
      "category": "security|swift-best-practices|iso-compliance|testing|code-quality",
      "title": "Brief issue title",
      "description": "Detailed explanation of the issue",
      "suggestion": "How to fix it",
      "code_example": "// Example of better code (optional)"
    }}
  ],
  "positive_notes": [
    "Things that were done well"
  ]
}}

Be thorough but fair. Flag real issues, not stylistic nitpicks unless they impact security or maintainability.
"""
    
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return message.content[0].text

def parse_review(review_text):
    """Parse Claude's JSON response"""
    # Claude might wrap JSON in markdown code blocks
    if "```json" in review_text:
        start = review_text.find("```json") + 7
        end = review_text.find("```", start)
        review_text = review_text[start:end].strip()
    elif "```" in review_text:
        start = review_text.find("```") + 3
        end = review_text.find("```", start)
        review_text = review_text[start:end].strip()
    
    return json.loads(review_text)

def post_review_comment(review_data):
    """Post review as PR comment"""
    issues = review_data.get('issues', [])
    positive = review_data.get('positive_notes', [])
    summary = review_data.get('summary', '')
    severity = review_data.get('severity', 'low')
    
    # Build comment
    comment = f"""## 🤖 AI Code Review
    
**Summary:** {summary}

**Overall Severity:** {severity.upper()}

"""
    
    if issues:
        comment += "### Issues Found\n\n"
        for issue in issues:
            emoji = {
                'critical': '🚨',
                'high': '⚠️',
                'medium': '⚡',
                'low': 'ℹ️'
            }.get(issue['severity'], 'ℹ️')
            
            comment += f"{emoji} **{issue['title']}** ({issue['severity']})\n"
            comment += f"- **File:** `{issue['file']}`"
            if issue.get('line'):
                comment += f" (line {issue['line']})"
            comment += f"\n- **Category:** {issue['category']}\n"
            comment += f"- **Issue:** {issue['description']}\n"
            if issue.get('suggestion'):
                comment += f"- **Suggestion:** {issue['suggestion']}\n"
            if issue.get('code_example'):
                comment += f"\n```swift\n{issue['code_example']}\n```\n"
            comment += "\n"
    
    if positive:
        comment += "### ✅ Positive Notes\n\n"
        for note in positive:
            comment += f"- {note}\n"
    
    comment += "\n---\n*This review was performed by Claude AI. Please verify all suggestions.*"
    
    # Write comment to file
    with open('/tmp/review_comment.md', 'w') as f:
        f.write(comment)
    
    # Post using GitHub CLI
    pr_number = os.environ['PR_NUMBER']
    repo = os.environ['REPO']
    
    subprocess.run([
        'gh', 'pr', 'comment', pr_number,
        '--repo', repo,
        '--body-file', '/tmp/review_comment.md'
    ], env=os.environ)
    
    # Exit with error if critical issues found
    critical_issues = [i for i in issues if i['severity'] == 'critical']
    if critical_issues:
        print(f"❌ Found {len(critical_issues)} critical issue(s)")
        sys.exit(1)
    else:
        print("✅ Review complete")

def main():
    print("🔍 Starting AI code review...")
    
    # Get diff and changed files
    diff = get_diff()
    changed_files = get_changed_files()
    
    if not changed_files:
        print("No Swift files changed, skipping review")
        return
    
    print(f"Reviewing {len(changed_files)} file(s)...")
    
    # Get file contents for context
    file_contents = {
        filepath: get_file_content(filepath)
        for filepath in changed_files
    }
    
    # Get AI review
    review_text = review_code(diff, changed_files, file_contents)
    
    # Parse and post
    try:
        review_data = parse_review(review_text)
        post_review_comment(review_data)
    except json.JSONDecodeError as e:
        print(f"Failed to parse review: {e}")
        print("Raw response:")
        print(review_text)
        sys.exit(1)

if __name__ == '__main__':
    main()