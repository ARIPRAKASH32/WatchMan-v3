def calculate_confidence(alert_type, match_count, threshold, base_conf=70):
    """Calculate confidence based on how much the threshold is exceeded."""
    if match_count <= threshold:
        return base_conf
    
    excess_ratio = match_count / threshold
    conf = base_conf + ((excess_ratio - 1) * 20)
    return min(int(conf), 99)
