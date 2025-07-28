# aitm-detect

Detects anti-AiTM (Adversary-in-the-Middle) measures in Microsoft login page custom CSS branding. See the blog: https://advancedredteaming.nl/posts/detecteren-en-omzeilen-van-anti-adversary-in-the-middle-aitm-tokens

## Installation

```bash
pip install requests
```

## Usage

Check a single domain:
```bash
python aitm_detect.py -d example.com
```

Check multiple domains from a file:
```bash
python aitm_detect.py -l domains.txt
```

## What it does

- Checks Microsoft login pages for custom CSS company branding
- Extracts and analyzes CSS content for external image URLs
- Identifies potential anti-AiTM security measures
