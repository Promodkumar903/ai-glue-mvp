
from config import Config

def assess_risk(prompt):
    high = Config.HIGH_RISK_KEYWORDS
    med = Config.MEDIUM_RISK_KEYWORDS
    if any(k in prompt.lower() for k in high):
        return 'HIGH'
    if any(k in prompt.lower() for k in med):
        return 'MEDIUM'
    return 'LOW'
